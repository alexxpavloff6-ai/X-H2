"""Read selected Fuji MakerNote entries through EXIF pointers, without writing photographs.

The RAF case examines the EXIF of the embedded JPEG, not proprietary raw sensor data.
Values are reported as stored bytes; interpretation is external to this parser.
"""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
DIR = ROOT / 'Тестовые фото'
REDEVELOPED = DIR / 'Доработка 296 в камере'
TAGS = {0x1003: 'Saturation', 0x1040: 'ShadowTone', 0x1041: 'HighlightTone',
        0x1048: 'ColorChromeEffect', 0x104e: 'ColorChromeFXBlue',
        0x1401: 'FilmMode', 0x1436: 'ImageGeneration'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def jpeg_exif(jpeg):
    if jpeg[:2] != b'\xff\xd8':
        raise ValueError('No JPEG SOI')
    pos = 2
    while pos + 4 <= len(jpeg):
        if jpeg[pos] != 0xff:
            raise ValueError('Invalid JPEG marker')
        while jpeg[pos] == 0xff:
            pos += 1
        marker = jpeg[pos]
        pos += 1
        if marker in (0xda, 0xd9):
            break
        if marker == 1 or 0xd0 <= marker <= 0xd7:
            continue
        length = int.from_bytes(jpeg[pos:pos+2], 'big')
        if length < 2 or pos + length > len(jpeg):
            raise ValueError('Invalid JPEG segment')
        if marker == 0xe1 and jpeg[pos+2:pos+8] == b'Exif\x00\x00':
            return jpeg[pos+8:pos+length]
        pos += length
    raise ValueError('EXIF APP1 not found')


def read_ifd(blob, offset, order):
    if offset + 2 > len(blob):
        raise ValueError('IFD offset out of bounds')
    count = struct.unpack_from(order + 'H', blob, offset)[0]
    if offset + 2 + 12 * count + 4 > len(blob):
        raise ValueError('IFD table out of bounds')
    rows = []
    for i in range(count):
        start = offset + 2 + i * 12
        tag, kind, number = struct.unpack_from(order + 'HHI', blob, start)
        rows.append((tag, kind, number, blob[start+8:start+12], start))
    return rows


def unique(rows, tag, typ, count):
    found = [r for r in rows if r[0] == tag]
    if len(found) != 1 or found[0][1:3] != (typ, count):
        raise ValueError(f'Unexpected entry 0x{tag:04x}')
    return found[0]


def parse_jpeg(jpeg):
    tiff = jpeg_exif(jpeg)
    order = {b'II': '<', b'MM': '>'}.get(tiff[:2])
    if order is None or struct.unpack_from(order + 'H', tiff, 2)[0] != 42:
        raise ValueError('Invalid TIFF header')
    ifd0 = struct.unpack_from(order + 'I', tiff, 4)[0]
    exif_link = unique(read_ifd(tiff, ifd0, order), 0x8769, 4, 1)
    exif_offset = struct.unpack(order + 'I', exif_link[3])[0]
    maker_link = [r for r in read_ifd(tiff, exif_offset, order) if r[0] == 0x927c]
    if len(maker_link) != 1 or maker_link[0][1] != 7:
        raise ValueError('Missing MakerNote pointer')
    _, _, size, value, _ = maker_link[0]
    offset = struct.unpack(order + 'I', value)[0]
    maker = tiff[offset:offset+size]
    if len(maker) != size or maker[:8] != b'FUJIFILM':
        raise ValueError('Invalid Fuji MakerNote')
    fuji_ifd = struct.unpack_from('<I', maker, 8)[0]
    rows = read_ifd(maker, fuji_ifd, '<')
    out = {}
    for tag, name in TAGS.items():
        matches = [r for r in rows if r[0] == tag]
        if not matches:
            continue
        if len(matches) != 1:
            raise ValueError(f'Duplicate tag {name}')
        _, kind, count, value, at = matches[0]
        if count != 1 or kind not in (3, 4, 9):
            raise ValueError(f'Unexpected type/count for {name}: {kind}/{count}')
        fmt = {3: '<H', 4: '<I', 9: '<i'}[kind]
        out[name] = {'tag': f'0x{tag:04x}', 'type': kind, 'count': count,
                     'ifd_entry_hex': maker[at:at+12].hex(),
                     'value': struct.unpack_from(fmt, value)[0]}
    return out


paths = []
for i in range(292, 300):
    paths.append((DIR / f'DSCF{i:04d}.RAF', 'RAF_embedded_JPEG'))
    jpg = DIR / f'DSCF{i:04d}.JPG'
    if jpg.exists():
        paths.append((jpg, 'camera_JPEG'))
for i in (300, 301, 302):
    paths.append((REDEVELOPED / f'DSCF{i:04d}.JPG', 'camera_redeveloped_JPEG'))
results = []
for path, kind in paths:
    data = path.read_bytes()
    before = sha(data)
    if kind == 'RAF_embedded_JPEG':
        if data[:16] != b'FUJIFILMCCD-RAW ':
            raise ValueError('Invalid RAF signature')
        offset, length = struct.unpack_from('>II', data, 84)
        jpeg = data[offset:offset+length]
        if len(jpeg) != length:
            raise ValueError('Invalid embedded preview length')
    else:
        jpeg = data
    result = {'file': path.name, 'kind': kind, 'sha256_before': before, 'tags': parse_jpeg(jpeg)}
    del jpeg, data
    result['sha256_after'] = sha(path.read_bytes())
    if result['sha256_after'] != before:
        raise RuntimeError(f'Input changed: {path.name}')
    results.append(result)
output = {'description': 'JPEG APP1 EXIF -> TIFF IFD0 -> ExifIFD 0x927c -> Fuji MakerNote IFD. RAF metadata here is from embedded JPEG only. Values are stored bytes; tags do not prove execution path or pixel processing.', 'source': 'https://exiftool.org/TagNames/FujiFilm.html', 'files': results}
(HERE / 'байты.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for item in results:
    tags = item['tags']
    print(item['file'], item['kind'], 'FilmMode=', tags.get('FilmMode', {}).get('value'), 'Saturation=', tags.get('Saturation', {}).get('value'), 'ImageGeneration=', tags.get('ImageGeneration', {}).get('value'))
