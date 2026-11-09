"""Compare the uncompressed strip of DSCF0296.RAF with LibRaw's decoded raw_image.
Only numerical aggregate counts and hashes are stored, never image pixels or metadata IDs.
"""
from pathlib import Path
import hashlib
import json
import numpy as np
import rawpy

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[2]
ROOT = ANALYSIS.parent
path = ROOT / 'Тестовые фото/DSCF0296.RAF'
metadata_path = ANALYSIS / 'Проявка_0296/Метаданные/метаданные.json'
meta = json.loads(metadata_path.read_text(encoding='utf-8'))['files'][path.name]
tags = meta['numeric']

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

before = sha(path)
if before != meta['sha256_before']:
    raise ValueError('RAW differs from metadata reference')
width, height = tags['FujiIFD:RawImageFullWidth'], tags['FujiIFD:RawImageFullHeight']
offset, length = tags['FujiIFD:StripOffsets'], tags['FujiIFD:StripByteCounts']
if length != width * height * 2 or offset + length > path.stat().st_size:
    raise ValueError('Unexpected or truncated strip')
if tags['RAF:RAFCompression'] != 0:
    raise ValueError('Not the expected uncompressed RAF')
rawle = np.memmap(path, dtype='<u2', mode='r', offset=offset, shape=(height, width))
rawbe = np.memmap(path, dtype='>u2', mode='r', offset=offset, shape=(height, width))
count = mismatches_le = mismatches_be = outside_14bit = 0
with rawpy.imread(str(path)) as raw:
    if raw.raw_image.shape != (height, width):
        raise ValueError('Unexpected LibRaw full mosaic dimensions')
    for start in range(0, height, 128):
        end = min(start + 128, height)
        decoded = raw.raw_image[start:end, :]
        le, be = rawle[start:end, :], rawbe[start:end, :]
        count += decoded.size
        mismatches_le += int(np.count_nonzero(le != decoded))
        mismatches_be += int(np.count_nonzero(be != decoded))
        outside_14bit += int(np.count_nonzero(le > 0x3fff))
del rawle, rawbe
after = sha(path)
assert before == after
result = {'method': 'Uncompressed FujiIFD strip from previously extracted ExifTool metadata; compare every 16-bit sample with rawpy/LibRaw raw_image, before demosaic. Big-endian interpretation is a negative control. This verifies bytes of this file against this decoder, not the camera recording process or other RAF formats.',
          'file': path.name, 'sha256_before': before, 'sha256_after': after,
          'width': width, 'height': height, 'strip_offset_bytes': offset, 'strip_length_bytes': length,
          'reported_bits_per_sample': tags['FujiIFD:BitsPerSample'], 'sample_count': count,
          'mismatches_little_endian': mismatches_le, 'mismatches_big_endian_control': mismatches_be,
          'samples_greater_than_16383': outside_14bit, 'numpy_version': np.__version__, 'rawpy_version': rawpy.__version__}
(HERE / 'результат.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False, indent=2))
