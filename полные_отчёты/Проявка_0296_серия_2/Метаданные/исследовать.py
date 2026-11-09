#!/usr/bin/env python3
"""Локальный анализ RAF/JPEG; запуск: python исследовать.py --exiftool ПУТЬ [--perl ПУТЬ]."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).with_name('метаданные.json')
PRIVATE = re.compile(r'(?i)(gps|serial|owner|artist|copyright|creator|author|face|location|position|latitude|longitude|altitude|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?(number|count)|directory|filename|sourcefile|comment|description|subject|keywords)')
UNKNOWN = re.compile(r'(?i)(?:0x[0-9a-f]+|unknown)')
IDENTIFIER = re.compile(r'(?i)(serial|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?(?:number|count))')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def headers(data):
    if data[:2] != b'\xff\xd8':
        raise ValueError('Не JPEG')
    pos, segments, dqt, icc = 2, [], [], 0
    while pos < len(data):
        if data[pos] != 255:
            raise ValueError('Некорректный JPEG до первого SOS')
        while pos < len(data) and data[pos] == 255:
            pos += 1
        if pos >= len(data):
            raise ValueError('Оборванный JPEG')
        marker = data[pos]
        pos += 1
        if marker in (0xda, 0xd9):
            segments.append({'marker': f'{marker:02X}'})
            break
        if marker == 1 or 0xd0 <= marker <= 0xd7:
            segments.append({'marker': f'{marker:02X}'})
            continue
        length = int.from_bytes(data[pos:pos + 2], 'big')
        if length < 2 or pos + length > len(data):
            raise ValueError('Неверная длина JPEG-сегмента')
        payload = data[pos + 2:pos + length]
        segments.append({'marker': f'{marker:02X}', 'length': length})
        if marker == 0xdb:
            dqt.append(digest(payload))
        if marker == 0xe2 and payload.startswith(b'ICC_PROFILE\x00'):
            icc += 1
        pos += length
    else:
        raise ValueError('Нет SOS или EOI')
    return {'segments_before_first_scan': segments, 'dqt_payload_sha256': dqt,
            'icc_app2_segments_before_first_scan': icc}


def safe(tags):
    return {k: v for k, v in tags.items() if ':' in k and not k.startswith('System:')
            and not PRIVATE.search(k) and not UNKNOWN.search(k)
            and not (isinstance(v, str) and v.startswith('(Binary data'))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exiftool', required=True)
    parser.add_argument('--perl')
    args = parser.parse_args()
    cmd = ([args.perl] if args.perl else []) + [args.exiftool]
    version = subprocess.run(cmd + ['-ver'], check=True, capture_output=True, text=True).stdout.strip()
    photos = ROOT / 'Тестовые фото'
    parent = photos / 'Доработка 296 в камере'
    paths = [photos / 'DSCF0296.RAF', parent / 'DSCF0300.JPG'] + [parent / 'Доработка 2' / f'DSCF{i:04d}.JPG' for i in range(303, 311)]
    before = {p.name: digest(p.read_bytes()) for p in paths}
    raw = {}
    result = {'method': {'exiftool_version': version, 'arguments': '-j -G1:4 -a -u -U -charset UTF8; отдельно с -n и без него',
              'numeric': '-n отключает PrintConv, но не ValueConv; не обязательно исходное значение.',
              'unknown': 'Неизвестные теги сравниваются без публикации значений: их смысл и приватность не установлены. Неизвестные массивы RAF исключены.',
              'privacy': 'Идентификаторы только наличие и равенство; GPS, строки с личной информацией и бинарные данные не публикуются.',
              'relationship': 'Происхождение из RAF и последовательность сообщены владельцем; EXIF не доказывает происхождение пикселей.'}, 'files': {}}
    def extract(data, numeric):
        opts = ['-j', '-G1:4', '-a', '-u', '-U', '-charset', 'UTF8'] + (['-n'] if numeric else [])
        return json.loads(subprocess.run(cmd + opts + ['-'], input=data, capture_output=True, check=True).stdout)[0]
    for p in paths:
        data = p.read_bytes()
        numeric, display = extract(data, True), extract(data, False)
        raw[p.name] = numeric
        item = {'size_bytes': len(data), 'sha256_before': before[p.name], 'numeric': safe(numeric), 'display': safe(display)}
        if p.suffix.upper() == '.JPG':
            item['jpeg_headers'] = headers(data)
        result['files'][p.name] = item
    base = raw['DSCF0300.JPG']
    result['differences_vs_0300'] = {}
    result['unknown_comparison_vs_0300'] = {}
    result['identifier_comparison_vs_0300'] = {}
    for name, tags in raw.items():
        if name == 'DSCF0300.JPG':
            continue
        a, b = safe(base), safe(tags)
        result['differences_vs_0300'][name] = {k: {'0300': a.get(k), 'file': b.get(k), 'in_0300': k in a, 'in_file': k in b}
            for k in sorted(a.keys() | b.keys()) if k not in a or k not in b or a[k] != b[k]}
        unknown_keys = {k for k in base.keys() | tags.keys() if UNKNOWN.search(k) and not PRIVATE.search(k) and not k.startswith('RAF:FujiFilm_RAFData_')}
        result['unknown_comparison_vs_0300'][name] = {k: {'in_0300': k in base, 'in_file': k in tags, 'equal': base[k] == tags[k] if k in base and k in tags else None}
            for k in sorted(unknown_keys)}
        ident_keys = {k for k in base.keys() | tags.keys() if IDENTIFIER.search(k)}
        result['identifier_comparison_vs_0300'][name] = {k: {'in_0300': k in base, 'in_file': k in tags, 'equal': base[k] == tags[k] if k in base and k in tags else None}
            for k in sorted(ident_keys)}
    after = {p.name: digest(p.read_bytes()) for p in paths}
    for name, item in result['files'].items():
        item['sha256_after'] = after[name]
        item['unchanged'] = item['sha256_before'] == after[name]
    if not all(item['unchanged'] for item in result['files'].values()):
        raise RuntimeError('Вход изменился при анализе; JSON не записан')
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Сохранено:', OUT, '; ExifTool', version)


if __name__ == '__main__':
    main()
