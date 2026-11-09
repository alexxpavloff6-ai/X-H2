"""Извлечение JPEG X100VI и поиск буквальных ссылок; DAT не изменяется.
Запуск: python исследовать_изображение.py (нужны Pillow и зависимости анализ_файла.py).
"""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
from PIL import Image

HERE = Path(__file__).resolve().parent
AN = HERE.parent.parent
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
source = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
raw = source.read_bytes()
hash256 = lambda b: hashlib.sha256(b).hexdigest()
assert hash256(raw) == '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
data = raw.translate(base.TRANSLATION)
off = 0x4402bc
usize, csize, pages, page_size, alignment = struct.unpack_from('<5I', data, off)
jpeg = base.unpack_fflz(data, off)
(HERE / 'изображение.jpg').write_bytes(jpeg)
with Image.open(HERE / 'изображение.jpg') as im:
    im.load()
    size, mode = im.size, im.mode
    # Полоса одинаковой высоты, координаты именуются включительно/исключительно.
    crops = []
    for top in range(0, im.height, 512):
        bottom = min(im.height, top + 512)
        name = f'полоса_{top:05d}_{bottom:05d}.png'
        im.crop((0, top, im.width, bottom)).save(HERE / name)
        crops.append({'file': name, 'y_start': top, 'y_end_exclusive': bottom})
    # Высота 9120 = 19 × 480: видимые границы совпадают с этим шагом.
    panels = []
    assert im.size == (640, 9120)
    for index in range(19):
        top = index * 480
        name = f'кадр_{index + 1:02d}.png'
        im.crop((0, top, 640, top + 480)).save(HERE / name)
        panels.append({'index_one_based': index + 1, 'y_start': top,
                       'y_end_exclusive': top + 480, 'file': name})
regions = {'DAT_XOR_FF': data}
pattern = bytes.fromhex('0040000004000000')
blocks = []
for m in re.finditer(re.escape(pattern), data):
    p = m.start() - 12
    if p < 0: continue
    u, c, n, ps, al = struct.unpack_from('<5I', data, p)
    if not (20 < c < u < 256*2**20 and (c+16383)//16384 == n and p+c <= len(data)): continue
    try: b = base.unpack_fflz(data, p)
    except (ValueError, IndexError): continue
    regions[f'FFLZ_{p:#x}'] = b
    blocks.append({'offset': hex(p), 'packed': c, 'unpacked': u})
# Код показан в координатах распакованного блока, не DAT и не RAM.
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
code = regions['FFLZ_0x1402bc']
lines = ['; AArch64, смещения от начала распакованного FFLZ DAT 0x1402bc.',
         '; Целевые адреса PC-relative в той же условной системе; не адреса DAT/RAM.']
for start, end in ((0x1304, 0x1384), (0x1514, 0x159c),
                   (0x159c, 0x167c), (0x16ec, 0x17e8),
                   (0x17e8, 0x1bc4)):
    lines.append(f'\n; [{start:#x}, {end:#x})')
    for ins in cs.disasm(code[start:end], start):
        lines.append(f'{ins.address:08x}  {ins.bytes.hex(" "):11}  {ins.mnemonic:8} {ins.op_str}')
(HERE / 'код_recovery.asm').write_text('\n'.join(lines)+'\n', encoding='utf-8')
# Search aligned and unaligned little/big-endian literals; not proof of xrefs.
values = {'header_dat_offset': off, 'payload_dat_offset': off+20,
          'packed_size': csize, 'unpacked_size': usize}
hits = {}
for region, buf in regions.items():
    for label, value in values.items():
        for endian in ('little', 'big'):
            pat = value.to_bytes(4, endian)
            offsets = [hex(m.start()) for m in re.finditer(re.escape(pat), buf)]
            if offsets: hits[f'{region}:{label}:{endian}'] = offsets
# Наличие текстовых имен не доказывает обращение к данному JPEG.
terms = re.compile(rb'restor(?:ation|e|ing)|recover(?:y|ing)?|jpeg', re.I)
strings = []
for region, buf in regions.items():
    for m in re.finditer(rb'[\x20-\x7e]{6,}', buf):
        if terms.search(m.group()):
            strings.append({'region': region, 'offset': hex(m.start()),
                            'text': m.group()[:240].decode('ascii')})
(HERE / 'строки_поиска.json').write_text(
    json.dumps(strings, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
# QR читается опционально OpenCV; кадры сохраняются независимо от его наличия.
qr = []
try:
    import cv2, numpy as np
    detector = cv2.QRCodeDetector()
    for index in (2, 15, 16, 17, 18, 19):
        buf = (HERE / f'кадр_{index:02d}.png').read_bytes()
        image = cv2.imdecode(np.frombuffer(buf, np.uint8), cv2.IMREAD_COLOR)
        text, points, _ = detector.detectAndDecode(image)
        qr.append({'panel': index, 'detected': points is not None, 'text': text})
except ImportError:
    qr = None
result = {'source': str(source.relative_to(ROOT)), 'source_bytes': len(raw),
          'source_sha256': hash256(raw), 'source_sha256_after': hash256(source.read_bytes()),
          'transform': 'XOR ff for each DAT byte; offsets unchanged',
          'fflz_dat_offset': hex(off), 'fflz_header_le_words': [usize,csize,pages,page_size,alignment],
          'packed_transformed_sha256': hash256(data[off:off+csize]),
          'jpeg_bytes': len(jpeg), 'jpeg_sha256': hash256(jpeg), 'jpeg_md5': hashlib.md5(jpeg).hexdigest(),
          'jpeg_soi': jpeg[:2].hex(), 'jpeg_last_16': jpeg[-16:].hex(),
          'jpeg_eoi_offsets': [hex(m.start()) for m in re.finditer(b'\xff\xd9', jpeg)],
          'image_width_height': size, 'mode': mode, 'crops': crops, 'panels': panels,
          'scan': '00 40 00 00 04 00 00 00 at header+12; valid size and decoding; other variants not excluded',
          'blocks': blocks, 'literal_hits': hits, 'matching_strings_file': 'строки_поиска.json',
          'qr_opencv': qr,
          'recovery_link_evidence': {
              'fflz_1402bc_header_u64le': [hex(x) for x in struct.unpack_from('<8Q', code)],
              'dispatch_table_offset': '0x14a3b8',
              'dispatch_table_six_rows_hex': code[0x14a3b8:0x14a3b8+6*0x48].hex(),
              'dat_xor_ff_u64_at_0x120394': hex(struct.unpack_from('<Q', data, 0x120394)[0]),
              'dat_xor_ff_u64_at_0x1203b4': hex(struct.unpack_from('<Q', data, 0x1203b4)[0]),
              'code_relocated_to_0x881000_adrp_add_at_0x1afc': '0x681000',
              'code_relocated_to_0x881000_adrp_add_at_0x1b10': '0x925c5'}}
(HERE / 'доказательства.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False, indent=2))
