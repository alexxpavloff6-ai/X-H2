"""Exploratory CIELAB interpolation and hue check on three existing JPEGs.
Only aggregate outputs and input hashes are saved, never images.
"""
from pathlib import Path
import hashlib
import json
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = ROOT / 'Тестовые фото/Доработка 296 в камере'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


images, hashes = {}, {}
for n in (300, 301, 302):
    p = SOURCE / f'DSCF{n:04d}.JPG'
    before = sha(p)
    img = cv2.imdecode(np.fromfile(p, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None or img.shape != (5152, 7728, 3):
        raise ValueError(f'Unexpected JPEG: {p.name}')
    images[n] = cv2.resize(img, (966, 644), interpolation=cv2.INTER_AREA)
    del img
    after = sha(p)
    if before != after:
        raise RuntimeError(f'Input changed: {p.name}')
    hashes[p.name] = before
lab = {n: cv2.cvtColor(im.astype(np.float32) / 255, cv2.COLOR_BGR2LAB)
       for n, im in images.items()}
c = {n: np.hypot(z[:, :, 1], z[:, :, 2]) for n, z in lab.items()}
mask = np.ones((644, 966), dtype=bool)
for im in images.values():
    mask &= np.all((im > 5) & (im < 250), axis=2)
d1, d2 = c[300] - c[301], c[302] - c[301]
mask &= (lab[301][:, :, 0] > 15) & (lab[301][:, :, 0] < 85) & (c[301] > 10) & (d2 > 1)
a, b = d1[mask], d2[mask]
if not len(a):
    raise ValueError('Empty mask')
ratio = a / b
h0 = np.arctan2(lab[301][:, :, 2], lab[301][:, :, 1])
h2 = np.arctan2(lab[302][:, :, 2], lab[302][:, :, 1])
dh = np.degrees(np.arctan2(np.sin(h2 - h0), np.cos(h2 - h0)))[mask]
result = {'method': 'Exploratory, reduced area 966x644; JPEG EXIF sRGB assumed, OpenCV BGR2Lab float. C=sqrt(a^2+b^2), signed hue angle atan2(b,a). Mask RGB 6..249 for all three reduced images, reference 0301 L* 15..85 and C*>10, and C*(0302)-C*(0301)>1. No registration. Selection conditioned on observed outcome; not causal proof. 6/13 derives from previously measured synthetic gain differences (134-128)/(141-128), not an inferred camera formula.',
          'source_sha256': hashes, 'opencv_version': cv2.__version__, 'numpy_version': np.__version__,
          'mask_fraction': float(mask.mean()), 'mask_pixels': int(mask.sum()),
          'fractional_step_median': float(np.median(ratio)), 'fractional_step_mean': float(np.mean(ratio)),
          'fractional_step_p10_p50_p90': [float(v) for v in np.percentile(ratio, [10, 50, 90])],
          'origin_constrained_ls_slope': float(np.dot(a, b) / np.dot(b, b)),
          'mae_6_over_13': float(np.mean(np.abs(a - (6 / 13) * b))),
          'mae_half': float(np.mean(np.abs(a - 0.5 * b))),
          'signed_hue_diff_degrees_p05_p25_p50_p75_p95': [float(v) for v in np.percentile(dh, [5, 25, 50, 75, 95])],
          'median_absolute_hue_diff_degrees': float(np.median(np.abs(dh)))}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k: v for k, v in result.items() if k not in ('method', 'source_sha256')}, ensure_ascii=False, indent=2))
