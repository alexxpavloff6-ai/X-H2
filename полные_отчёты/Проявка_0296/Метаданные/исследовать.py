#!/usr/bin/env python3
"""Сравнение метаданных: входы только читаются; Python 3 и ExifTool.
Запуск из любого каталога: python исследовать.py --exiftool ПУТЬ [--perl ПУТЬ].
Создаёт метаданные.json только рядом со сценарием, без приватных тегов.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).with_name('метаданные.json')
PRIVATE = re.compile(r'(?i)(gps|serial|owner|artist|copyright|creator|author|face|location|position|latitude|longitude|altitude|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?(number|count)|directory|filename|sourcefile|comment|description|subject|keywords)')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def jpeg_headers(data):
    if data[:2] != b'\xff\xd8':
        raise ValueError('Не JPEG')
    pos, dqt, icc = 2, [], 0
    while pos < len(data):
        if data[pos] != 0xff:
            raise ValueError('Неверная структура JPEG')
        while data[pos] == 0xff:
            pos += 1
        marker = data[pos]
        pos += 1
        if marker in (0xda, 0xd9):
            break
        if marker == 1 or 0xd0 <= marker <= 0xd7:
            continue
        length = int.from_bytes(data[pos:pos+2], 'big')
        if length < 2 or pos + length > len(data):
            raise ValueError('Неверная длина JPEG-сегмента')
        payload = data[pos+2:pos+length]
        if marker == 0xdb:
            dqt.append(digest(payload))
        if marker == 0xe2 and payload.startswith(b'ICC_PROFILE\x00'):
            icc += 1
        pos += length
    return {'dqt_payload_sha256': dqt, 'icc_app2_segments_before_sos': icc}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exiftool', required=True)
    parser.add_argument('--perl')
    args = parser.parse_args()
    cmd = ([args.perl] if args.perl else []) + [args.exiftool]
    version = subprocess.run(cmd + ['-ver'], check=True, capture_output=True, text=True).stdout.strip()
    paths = [ROOT / 'Тестовые фото' / 'DSCF0296.RAF'] + [ROOT / 'Тестовые фото' / 'Доработка 296 в камере' / f'DSCF{i:04d}.JPG' for i in (300, 301, 302)]
    before = {p.name: digest(p.read_bytes()) for p in paths}
    def extract(data, numeric=False):
        opts = ['-j', '-G1', '-a', '-u', '-charset', 'UTF8'] + (['-n'] if numeric else [])
        proc = subprocess.run(cmd + opts + ['-'], input=data, capture_output=True, check=True)
        return json.loads(proc.stdout)[0]
    def safe(tags):
        return {k: v for k, v in tags.items() if ':' in k and not k.startswith('System:') and not PRIVATE.search(k) and not (isinstance(v, str) and v.startswith('(Binary data'))}
    result = {'method': {'exiftool_version': version, 'numeric': '-n: ValueConv, не обязательно исходные байты', 'privacy': 'Приватные теги и бинарные данные не экспортируются; идентификаторы сравниваются только на равенство.', 'raf_relationship': 'Связь JPEG с данным RAF сообщена пользователем; метаданные не доказывают происхождение.'}, 'files': {}}
    raw_tags = {}
    for p in paths:
        data = p.read_bytes()
        numeric, display = extract(data, True), extract(data)
        raw_tags[p.name] = numeric
        item = {'size_bytes': len(data), 'sha256_before': before[p.name], 'numeric': safe(numeric), 'display': safe(display)}
        if p.suffix.upper() == '.JPG':
            item['jpeg_headers'] = jpeg_headers(data)
        if p.suffix.upper() == '.RAF':
            off, length, moff, mlen, ioff, ilen = struct.unpack('>6I', data[84:108])
            if data[:16] != b'FUJIFILMCCD-RAW ' or off + length > len(data) or data[off:off+2] != b'\xff\xd8':
                raise ValueError('Некорректная структура RAF')
            preview = data[off:off+length]
            item['raf_layout'] = {'preview_offset': off, 'preview_length': length, 'metadata_offset': moff, 'metadata_length': mlen, 'fuji_ifd_offset': ioff, 'fuji_ifd_length': ilen, 'compression_code': struct.unpack('>I', data[108:112])[0]}
            item['preview'] = {'sha256': digest(preview), 'numeric': safe(extract(preview, True)), 'display': safe(extract(preview))}
        result['files'][p.name] = item
    # Только факт наличия и равенства идентификаторов, без значений и хэшей.
    keys = sorted({k for tags in raw_tags.values() for k in tags if re.search(r'(?i)(serial|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?number)', k)})
    result['identifier_compatibility'] = {k: {'present': [name for name, tags in raw_tags.items() if k in tags], 'all_present_values_equal': len({json.dumps(tags[k], sort_keys=True) for tags in raw_tags.values() if k in tags}) <= 1} for k in keys}
    after = {p.name: digest(p.read_bytes()) for p in paths}
    for name, item in result['files'].items():
        item['sha256_after'] = after[name]
        item['unchanged'] = item['sha256_before'] == after[name]
    if not all(x['unchanged'] for x in result['files'].values()):
        raise RuntimeError('Вход изменился в ходе анализа')
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Сохранено:', OUT, '; ExifTool', version)

if __name__ == '__main__':
    main()
