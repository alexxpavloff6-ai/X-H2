# -*- coding: utf-8 -*-
"""Run from the repository root. Requires numpy, Pillow and opencv-python.
Read only the four source files, export only aggregated JSON, never images.
"""
from pathlib import Path
from io import BytesIO
import hashlib
import json
import platform

import cv2
import numpy as np
from PIL import Image, __version__ as pillow_version

ROOT = Path.cwd()
RAF = ROOT / 'Тестовые фото' / 'DSCF0296.RAF'
DIR = ROOT / 'Тестовые фото' / 'Доработка 296 в камере'
FILES = {'preview': RAF, **{f'030{i}': DIR / f'DSCF030{i}.JPG' for i in range(3)}}
OUT = ROOT / 'Анализ_прошивки' / 'Последовательное_исследование' / 'Этап_2' / 'Превью_и_проявки' / 'результаты.json'


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def digest_inputs():
    return {name: sha256(path) for name, path in FILES.items()}


def read_preview():
    data = RAF.read_bytes()
    if data[:16] != b'FUJIFILMCCD-RAW ':
        raise ValueError('Unexpected RAF signature')
    offset = int.from_bytes(data[84:88], 'big')
    length = int.from_bytes(data[88:92], 'big')
    if offset < 148 or length <= 0 or offset + length > len(data):
        raise ValueError('Invalid embedded JPEG bounds')
    image = Image.open(BytesIO(data[offset:offset + length]))
    image.load()
    return image, {'offset': offset, 'length': length}


def decode(image, size):
    info = {'original_size': list(image.size), 'orientation': image.getexif().get(274, 1),
            'exif_color_space': image.getexif().get(40961), 'has_icc': bool(image.info.get('icc_profile'))}
    if info['orientation'] != 1:
        raise ValueError('Unexpected orientation; automatic rotation is deliberately disabled')
    rgb = np.asarray(image.convert('RGB'))
    # All images get the identical normalized full-frame mapping and area downsampling.
    return cv2.resize(rgb, size, interpolation=cv2.INTER_AREA), info


def phase(ref, target):
    a = cv2.cvtColor(ref, cv2.COLOR_RGB2GRAY).astype(np.float32)
    b = cv2.cvtColor(target, cv2.COLOR_RGB2GRAY).astype(np.float32)
    window = cv2.createHanningWindow((a.shape[1], a.shape[0]), cv2.CV_32F)
    shift, response = cv2.phaseCorrelate(a, b, window)
    return {'target_relative_to_preview_xy': [float(x) for x in shift], 'response': float(response)}


def lab(rgb):
    return cv2.cvtColor(rgb.astype(np.float32) / 255.0, cv2.COLOR_RGB2LAB)


def summary(values):
    return {'mean': float(np.mean(values)), 'median': float(np.median(values)),
            'p05': float(np.percentile(values, 5)), 'p95': float(np.percentile(values, 95))}


def compare(ref, target, mask):
    a, b = lab(ref), lab(target)
    ac, bc = np.hypot(a[:, :, 1], a[:, :, 2]), np.hypot(b[:, :, 1], b[:, :, 2])
    da = b - a
    de = np.sqrt(np.sum(da * da, axis=2))
    result = {'n': int(mask.sum())}
    for i, k in enumerate(('L', 'a', 'b')):
        result[k] = {'preview': summary(a[:, :, i][mask]), 'target': summary(b[:, :, i][mask]),
                     'target_minus_preview': summary(da[:, :, i][mask])}
    result['C'] = {'preview': summary(ac[mask]), 'target': summary(bc[mask]),
                   'target_minus_preview': summary((bc - ac)[mask]),
                   'ratio_of_means_percent': float(100 * (bc[mask].mean() / ac[mask].mean() - 1)),
                   'fraction_increase': float(np.mean((bc - ac)[mask] > 0))}
    result['delta_E76'] = summary(de[mask])
    result['Yprime'] = {}
    for key, image in [('preview', ref), ('target', target)]:
        y = (image[:, :, 0] * .2126 + image[:, :, 1] * .7152 + image[:, :, 2] * .0722) / 255
        result['Yprime'][key] = summary(y[mask])
        pixels = image[mask]
        result['Yprime'][key]['fraction_any_0'] = float(np.any(pixels == 0, axis=1).mean())
        result['Yprime'][key]['fraction_any_255'] = float(np.any(pixels == 255, axis=1).mean())
    return result


def run(size, detail):
    image, info = read_preview()
    preview, preview_info = decode(image, size)
    image.close()
    arrays = {}
    infos = {'preview': {**preview_info, 'raf_jpeg': info}}
    for name in ('0300', '0301', '0302'):
        with Image.open(FILES[name]) as image:
            arrays[name], infos[name] = decode(image, size)
    h, w = preview.shape[:2]
    # A fixed 2% inset is common to every comparison. It accommodates fractional shifts
    # and excludes unstable frame edges, not selected content. 0300 determines translation.
    x0, x1, y0, y1 = int(w * .02), int(w * .98), int(h * .02), int(h * .98)
    core = np.s_[y0:y1, x0:x1]
    shifts = {name: phase(preview[core], img[core]) for name, img in arrays.items()}
    dx, dy = shifts['0300']['target_relative_to_preview_xy']
    if abs(dx) >= x0 or abs(dy) >= y0:
        raise ValueError('Measured shift exceeds inset; no safe common comparison region')
    transform = np.float32([[1, 0, -dx], [0, 1, -dy]])
    aligned = {name: cv2.warpAffine(img, transform, (w, h), flags=cv2.INTER_LINEAR,
                                   borderMode=cv2.BORDER_CONSTANT) for name, img in arrays.items()}
    mask = np.zeros((h, w), dtype=bool)
    mask[core] = True
    result = {'size': [w, h], 'common_crop_xyxy_exclusive': [x0, y0, x1, y1],
              'inputs': infos, 'translation_diagnostics': shifts,
              'applied_to_all_targets_xy': [-dx, -dy],
              'aligned_comparisons': {name: compare(preview, img, mask) for name, img in aligned.items()},
              'unregistered_0300': compare(preview, arrays['0300'], mask)}
    if detail:
        result['local_translation_0300'] = {}
        for iy in range(2):
            for ix in range(2):
                xa = x0 + (x1 - x0) * ix // 2
                xb = x0 + (x1 - x0) * (ix + 1) // 2
                ya = y0 + (y1 - y0) * iy // 2
                yb = y0 + (y1 - y0) * (iy + 1) // 2
                result['local_translation_0300'][f'{ix}_{iy}'] = phase(preview[ya:yb, xa:xb], arrays['0300'][ya:yb, xa:xb])
        result['regions_0300'] = {}
        for iy in range(2):
            for ix in range(2):
                m = np.zeros_like(mask)
                m[y0 + (y1-y0)*iy//2:y0 + (y1-y0)*(iy+1)//2,
                  x0 + (x1-x0)*ix//2:x0 + (x1-x0)*(ix+1)//2] = True
                result['regions_0300'][f'{ix}_{iy}'] = compare(preview, aligned['0300'], m)
        p_lab = lab(preview)
        c = np.hypot(p_lab[:, :, 1], p_lab[:, :, 2])
        result['preview_lightness_bins_0300'] = {}
        for lo, hi in ((0, 20), (20, 40), (40, 60), (60, 80), (80, 101)):
            m = mask & (p_lab[:, :, 0] >= lo) & (p_lab[:, :, 0] < hi)
            if m.any():
                result['preview_lightness_bins_0300'][f'{lo}-{hi}'] = compare(preview, aligned['0300'], m)
        result['preview_chroma_bins_0300'] = {}
        for lo, hi in ((0, 5), (5, 10), (10, 20), (20, 40), (40, 200)):
            m = mask & (c >= lo) & (c < hi)
            if m.any():
                result['preview_chroma_bins_0300'][f'{lo}-{hi}'] = compare(preview, aligned['0300'], m)
    return result


before = digest_inputs()
result = {'method': {'inputs': 'DSCF0296 RAF embedded JPEG vs 0300 camera rendering Color +1; 0301 Color 0 and 0302 Color +2 per user',
                     'grid': 'Normalized full frame resized using area to 1104x736, 2% common border excluded; sensitivity 552x368',
                     'registration': 'Hann-window phase correlation grayscale on common inset; translate all targets by inverse 0300 shift, bilinear interpolation',
                     'color': 'Assume encoded sRGB, OpenCV float Lab D65, C=sqrt(a²+b²), delta E76; Yprime is gamma-coded weighted RGB',
                     'limits': 'Preview is not full-resolution output; resizing and JPEG affect measurements; one scene, unknown preview recipe and hidden camera settings; no other exposure used'},
          'versions': {'python': platform.python_version(), 'numpy': np.__version__, 'pillow': pillow_version, 'opencv': cv2.__version__},
          'sha256_before': before, 'primary': run((1104, 736), True), 'half_grid_sensitivity': run((552, 368), False)}
result['sha256_after'] = digest_inputs()
result['inputs_unchanged'] = result['sha256_before'] == result['sha256_after']
OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
if not result['inputs_unchanged']:
    raise RuntimeError('Source hashes changed during analysis')
print('Wrote aggregate JSON; source hashes unchanged:', result['inputs_unchanged'])
