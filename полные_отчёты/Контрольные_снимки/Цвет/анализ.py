#!/usr/bin/env python3
"""Локальный анализ; исходные файлы не изменяются и изображения не сохраняются.
Запуск из любого каталога: python путь/к/анализ.py [путь/к/Тестовые фото].
Зависимости: numpy, Pillow, opencv-python. Результат рядом со сценарием.
"""
import io
import json
import struct
import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageOps, ImageCms

cv2.setNumThreads(1)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'Тестовые фото'
SIZE = (966, 644)  # одинаковая область кадра; усреднение при уменьшении
IDS = (292, 293, 294, 295, 296, 297, 298, 299)
JPG_IDS = (292, 293, 294, 295, 298, 299)
PAIRS = [(292, 295), (293, 294), (292, 293), (292, 294),
         (295, 293), (295, 294), (298, 299), (292, 298),
         (295, 299), (296, 297)]


def image_data(number, kind):
    path = SOURCE / f'DSCF{number:04d}.{kind}'
    if kind == 'RAF':
        with path.open('rb') as f:
            header = f.read(92)
            if header[:16] != b'FUJIFILMCCD-RAW ':
                raise ValueError(f'Не RAF: {path.name}')
            offset, length = struct.unpack('>II', header[84:92])
            f.seek(0, 2)
            if offset < 92 or length < 4 or offset + length > f.tell():
                raise ValueError(f'Неверные границы JPEG: {path.name}')
            f.seek(offset)
            data = f.read(length)
        if not data.startswith(b'\xff\xd8'):
            raise ValueError(f'Нет JPEG по смещению: {path.name}')
        im = Image.open(io.BytesIO(data))
    else:
        im = Image.open(path)
        offset = length = None
    exif = im.getexif()
    sub = exif.get_ifd(0x8769)
    icc = im.info.get('icc_profile')
    icc_name = None
    if icc:
        try:
            icc_name = ImageCms.getProfileName(ImageCms.ImageCmsProfile(io.BytesIO(icc))).strip()
        except (OSError, ValueError):
            icc_name = 'не распознан'
    def number_value(tag):
        value = sub.get(tag)
        return float(value) if value is not None else None
    meta = {'size_px': list(im.size), 'orientation': exif.get(274),
            'exif_color_space': sub.get(40961), 'icc_bytes': len(icc or b''),
            'icc_name': icc_name, 'exposure_s': number_value(33434),
            'f_number': number_value(33437), 'iso': number_value(34855),
            'exposure_bias_ev': number_value(37380), 'focal_mm': number_value(37386),
            'white_balance': sub.get(41987),
            'time_original': str(sub.get(36867, ''))[-8:] or None}
    if kind == 'RAF':
        meta.update(preview_offset=offset, preview_bytes=length)
    # No ICC transformation: all files must explicitly declare sRGB or be treated as assumed.
    rgb = np.asarray(ImageOps.exif_transpose(im).convert('RGB'))
    meta['native_any_channel_ge_254_pct'] = float(100 * np.mean(np.any(rgb >= 254, axis=2)))
    meta['native_any_channel_le_1_pct'] = float(100 * np.mean(np.any(rgb <= 1, axis=2)))
    meta['native_all_channels_ge_254_pct'] = float(100 * np.mean(np.all(rgb >= 254, axis=2)))
    rgb = cv2.resize(rgb, SIZE, interpolation=cv2.INTER_AREA)
    return rgb, meta


def lab(rgb):
    return cv2.cvtColor(rgb.astype(np.float32) / 255.0, cv2.COLOR_RGB2LAB)


def stats(rgb):
    l = lab(rgb)
    chroma = np.hypot(l[..., 1], l[..., 2])
    y = rgb.astype(np.float32) @ np.array([0.2126, 0.7152, 0.0722], np.float32)
    return {'Lstar_median': float(np.median(l[..., 0])),
            'Lstar_p05_p95': np.percentile(l[..., 0], [5, 95]).tolist(),
            'encoded_Y_median_0_255': float(np.median(y)),
            'chroma_median': float(np.median(chroma)),
            'chroma_p90': float(np.percentile(chroma, 90)),
            'any_channel_ge_254_pct': float(100 * np.mean(np.max(rgb, axis=2) >= 254)),
            'any_channel_le_1_pct': float(100 * np.mean(np.min(rgb, axis=2) <= 1)),
            'all_channels_ge_254_pct': float(100 * np.mean(np.min(rgb, axis=2) >= 254))}


def align(reference, target):
    # ECC warp maps reference coordinates into target coordinates (WARP_INVERSE_MAP).
    ref = cv2.cvtColor(reference, cv2.COLOR_RGB2GRAY).astype(np.float32) / 255
    tar = cv2.cvtColor(target, cv2.COLOR_RGB2GRAY).astype(np.float32) / 255
    warp = np.eye(2, 3, dtype=np.float32)
    try:
        corr, warp = cv2.findTransformECC(ref, tar, warp, cv2.MOTION_AFFINE,
            (cv2.TERM_CRITERIA_COUNT | cv2.TERM_CRITERIA_EPS, 200, 1e-6), None, 5)
    except cv2.error as e:
        return None, {'error': str(e).split('\n')[0]}
    flags = cv2.INTER_LINEAR | cv2.WARP_INVERSE_MAP
    aligned = cv2.warpAffine(target, warp, SIZE, flags=flags, borderMode=cv2.BORDER_CONSTANT)
    valid = cv2.warpAffine(np.ones(ref.shape, np.uint8), warp, SIZE,
                           flags=cv2.INTER_NEAREST | cv2.WARP_INVERSE_MAP) > 0
    return (aligned, valid), {'ecc_gray': float(corr), 'affine_ref_to_target': warp.tolist(),
        'center_shift_work_px': [float(warp[0, 0]*SIZE[0]/2 + warp[0, 1]*SIZE[1]/2 + warp[0, 2] - SIZE[0]/2),
                                 float(warp[1, 0]*SIZE[0]/2 + warp[1, 1]*SIZE[1]/2 + warp[1, 2] - SIZE[1]/2)],
        'area_scale': float(np.linalg.det(warp[:, :2])), 'overlap_pct': float(100*np.mean(valid))}


def comparison(a, b):
    aligned, result = align(a, b)
    if aligned is None:
        return result
    b, valid = aligned
    la, lb = lab(a), lab(b)
    ca, cb = np.hypot(la[..., 1], la[..., 2]), np.hypot(lb[..., 1], lb[..., 2])
    delta = lb - la
    de = np.linalg.norm(delta, axis=2)
    # Guard clipped/dark areas in both frames; additional tight L* matching is a selection,
    # not exposure correction and not a causal isolation of the color setting.
    guard = valid & (a.min(2) > 5) & (a.max(2) < 250) & (b.min(2) > 5) & (b.max(2) < 250)
    matched = guard & (np.abs(delta[..., 0]) <= 3) & (la[..., 0] >= 15) & (la[..., 0] <= 85)
    result['masks'] = {}
    for name, mask in [('overlap', valid), ('unclipped', guard), ('unclipped_Lmatched', matched)]:
        count = int(mask.sum())
        d = {'count': count, 'pct_work_frame': float(100 * mask.mean())}
        if count:
            d.update(delta_Lstar_median=float(np.median(delta[..., 0][mask])),
                     delta_chroma_median=float(np.median((cb-ca)[mask])),
                     delta_a_median=float(np.median(delta[..., 1][mask])),
                     delta_b_median=float(np.median(delta[..., 2][mask])),
                     deltaE76_median=float(np.median(de[mask])),
                     deltaE76_p90=float(np.percentile(de[mask], 90)),
                     rgb_abs_mae=float(np.mean(np.abs(a.astype(np.float32)-b.astype(np.float32))[mask])))
        result['masks'][name] = d
    return result


def main():
    imgs, meta = {}, {}
    for i in IDS:
        for kind in (['JPG', 'RAF'] if i in JPG_IDS else ['RAF']):
            rgb, info = image_data(i, kind)
            key = f'{i}_{kind}'
            imgs[key] = rgb
            info['stats'] = stats(rgb)
            meta[key] = info
    pairs = {}
    for a, b in PAIRS:
        kind = 'RAF' if a in (296, 297) else 'JPG'
        pairs[f'{a}_{b}_{kind}'] = comparison(imgs[f'{a}_{kind}'], imgs[f'{b}_{kind}'])
    for a, b in [(295, 296), (296, 298)]:
        pairs[f'{a}_{b}_RAF'] = comparison(imgs[f'{a}_RAF'], imgs[f'{b}_RAF'])
    previews = {str(i): comparison(imgs[f'{i}_JPG'], imgs[f'{i}_RAF']) for i in JPG_IDS}
    out = {'method': {'work_size': SIZE, 'interpolation': 'INTER_AREA downsample; linear affine',
            'lab': 'OpenCV float RGB2Lab; sRGB assumed where EXIF sRGB or unspecified',
            'comparison_direction': 'second minus first', 'registration': 'ECC affine grayscale',
            'unclipped': 'both images: each RGB channel >5 and <250 after resampling',
            'Lmatched': 'unclipped and |delta L*|<=3 and reference L* 15..85',
            'source_images_saved': False}, 'frames': meta, 'pairs': pairs, 'jpg_vs_raf_preview': previews}
    (HERE / 'результаты.json').write_text(json.dumps(out, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    # Content-free aggregate plot: no scene or metadata beyond frame numbers is shown.
    from PIL import ImageDraw
    canvas = Image.new('RGB', (1100, 480), 'white')
    draw = ImageDraw.Draw(canvas)
    colors = ['#d62728', '#1f77b4', '#2ca02c', '#9467bd', '#ff7f0e', '#222222']
    histograms = []
    for i in JPG_IDS:
        values = lab(imgs[f'{i}_JPG'])
        c = np.hypot(values[..., 1], values[..., 2])
        histograms.append([np.histogram(values[..., 0], bins=50, range=(0, 100))[0],
                           np.histogram(c, bins=50, range=(0, 120))[0]])
    for panel, title in enumerate(('L* lightness (0-100)', 'C*ab chroma (0-120)')):
        x0, y0, width, height = 50 + 540 * panel, 60, 470, 330
        maximum = max(h[panel].max() for h in histograms)
        draw.text((x0, 20), title, fill='black')
        draw.line([(x0, y0), (x0, y0 + height), (x0 + width, y0 + height)], fill='black', width=2)
        for j, hist in enumerate(histograms):
            points = [(x0 + (k + .5) * width / 50, y0 + height - height * value / maximum)
                      for k, value in enumerate(hist[panel])]
            draw.line(points, fill=colors[j], width=2)
        draw.text((x0, y0 + height + 7), '0', fill='black')
        draw.text((x0 + width - 20, y0 + height + 7), '100' if panel == 0 else '120', fill='black')
    for j, i in enumerate(JPG_IDS):
        draw.text((50 + j * 145, 430), f'{i}', fill=colors[j])
    canvas.save(HERE / 'распределения.png')
    print(f'Готово: {HERE / "результаты.json"}, {HERE / "распределения.png"}')


if __name__ == '__main__':
    main()
