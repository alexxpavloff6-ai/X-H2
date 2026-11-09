#!/usr/bin/env python3
"""Метаданные DSCF0292–0299; входы только читаются. Зависимости: Python 3.9+, ExifTool 13.61.

Запуск из корня проекта: python Анализ_прошивки/Контрольные_снимки/Метаданные/исследовать.py --exiftool PATH
PATH — исполняемый exiftool либо Perl-скрипт exiftool (тогда нужен --perl PATH).
Результат перезаписывает только собственный JSON рядом с этим сценарием.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INPUT = ROOT / 'Тестовые фото'
OUTPUT = Path(__file__).with_name('метаданные.json')
PRIVATE = re.compile(r'(?i)(gps|serial|owner|artist|copyright|creator|author|face|location|position|latitude|longitude|altitude|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?number)')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exiftool', required=True)
    ap.add_argument('--perl', help='интерпретатор для скрипта ExifTool')
    args = ap.parse_args()
    cmd = ([args.perl] if args.perl else []) + [args.exiftool]
    version = subprocess.run(cmd + ['-ver'], check=True, capture_output=True, text=True).stdout.strip()

    def metadata(data, numeric):
        switches = ['-j', '-G1', '-a', '-u', '-charset', 'UTF8']
        if numeric:
            switches += ['-n']
        proc = subprocess.run(cmd + switches + ['-'], input=data, capture_output=True, check=True)
        tags = json.loads(proc.stdout)[0]
        # По умолчанию не публикуем потенциально персональные идентификаторы,
        # GPS, имена и бинарные данные; системные даты относятся к временному потоку.
        return {k: v for k, v in tags.items() if ':' in k and not k.startswith('System:')
                and not PRIVATE.search(k) and not (isinstance(v, str) and v.startswith('(Binary data'))}

    result = {'method': {'exiftool_version': version, 'tool_url': 'https://exiftool.org/',
              'fuji_tag_reference': 'https://exiftool.org/TagNames/FujiFilm.html',
              'privacy': 'GPS, идентификаторы, лица и имена исключены; бинарные поля не сохраняются',
              'numeric': '-n, значения после ValueConv ExifTool, не всегда сырые байты тега',
              'display': 'стандартные форматированные значения ExifTool'}, 'files': {}}
    for index in range(292, 300):
        for ext in ('RAF', 'JPG'):
            path = INPUT / f'DSCF{index:04d}.{ext}'
            if not path.exists():
                continue
            data = path.read_bytes()
            item = {'size_bytes': len(data), 'sha256': sha(data),
                    'numeric': metadata(data, True), 'display': metadata(data, False)}
            if ext == 'RAF':
                if data[:16] != b'FUJIFILMCCD-RAW ':
                    raise ValueError(f'Не RAF: {path.name}')
                offset, length, meta_offset, meta_length, ifd_offset, ifd_length = struct.unpack('>6I', data[84:108])
                if offset + length > len(data) or ifd_offset + ifd_length > len(data):
                    raise ValueError(f'Выход за границы RAF: {path.name}')
                preview = data[offset:offset + length]
                if not preview.startswith(b'\xff\xd8'):
                    raise ValueError(f'Нет JPEG preview: {path.name}')
                item['raf_layout'] = {'preview_offset': offset, 'preview_length': length,
                    'raf_metadata_offset': meta_offset, 'raf_metadata_length': meta_length,
                    'fuji_ifd_offset': ifd_offset, 'fuji_ifd_length': ifd_length,
                    'compression_code_at_108': struct.unpack('>I', data[108:112])[0]}
                item['preview'] = {'size_bytes': len(preview), 'sha256': sha(preview),
                    'numeric': metadata(preview, True), 'display': metadata(preview, False)}
            result['files'][path.name] = item
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Сохранено: {OUTPUT}; файлов: {len(result["files"])}; ExifTool {version}')


if __name__ == '__main__':
    main()
