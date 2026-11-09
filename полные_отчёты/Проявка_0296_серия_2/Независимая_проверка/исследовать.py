"""Aggregated check of eight camera JPEGs against 0300, fixed 1:8 sampling.
Sources read only; no images or private metadata are saved.
"""
from pathlib import Path
import hashlib
import json
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DIR = ROOT / 'Тестовые фото/Доработка 296 в камере'
files = [DIR / 'DSCF0300.JPG'] + [DIR / 'Доработка 2' / f'DSCF{i:04d}.JPG' for i in range(303, 311)]

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

hashes = {}

def read_sample(path):
    before = sha(path)
    image = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None or image.shape != (5152, 7728, 3):
        raise ValueError(f'Unexpected JPEG: {path.name}')
    sample = image[::8, ::8, :].copy()
    del image
    after = sha(path)
    if before != after:
        raise RuntimeError(f'Input changed: {path.name}')
    hashes[path.name] = before
    return sample

reference = read_sample(files[0])
base = cv2.cvtColor(reference.astype(np.float32) / 255, cv2.COLOR_BGR2LAB)
base_c = np.hypot(base[:, :, 1], base[:, :, 2])
hue = np.mod(np.degrees(np.arctan2(base[:, :, 2], base[:, :, 1])), 360)
colorful = base_c >= 10
hue_counts = [int(np.count_nonzero(colorful & (hue >= lo) & (hue < lo + 30))) for lo in range(0, 360, 30)]
rows = []
for path in files[1:]:
    image = read_sample(path)
    lab = cv2.cvtColor(image.astype(np.float32) / 255, cv2.COLOR_BGR2LAB)
    delta = lab - base
    dc = np.hypot(lab[:, :, 1], lab[:, :, 2]) - base_c
    de = np.linalg.norm(delta, axis=2)
    bins = []
    for lo, hi in ((0,20),(20,40),(40,60),(60,80),(80,101)):
        mask = (base[:, :, 0] >= lo) & (base[:, :, 0] < hi)
        bins.append({'L_range': [lo, hi], 'samples': int(mask.sum()),
                     'mean_delta_L': float(delta[:, :, 0][mask].mean()),
                     'mean_delta_C': float(dc[mask].mean())})
    rows.append({'file': path.name, 'delta_lab_mean': [float(x) for x in delta.mean(axis=(0, 1))],
                 'delta_C_mean': float(dc.mean()), 'delta_C_median': float(np.median(dc)),
                 'delta_E76_mean': float(de.mean()), 'delta_E76_p50_p95': [float(x) for x in np.percentile(de, [50,95])],
                 'identical_rgb_fraction': float(np.mean(np.all(image == reference, axis=2))),
                 'delta_L_bins': bins})
output = {'method': 'Original JPEGs decoded as BGR, fixed pixels [::8,::8] sampled before float sRGB-to-CIELAB OpenCV conversion, no registration, no colorimetric calibration; differences are candidate minus DSCF0300. No repeated identical development baseline available, so small differences are not a noise floor or proof of causality. C* is not percent or firmware gain. Brightness bins assigned using 0300; hue counts limited to C* >=10.',
          'sampling_shape': list(reference.shape), 'source_sha256': hashes,
          'opencv_version': cv2.__version__, 'numpy_version': np.__version__,
          'hue_bin_counts_C_ge_10': hue_counts, 'comparisons': rows}
(HERE / 'результаты.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'sampling_shape': output['sampling_shape'], 'hue_counts': hue_counts,
                  'comparisons': [{k:r[k] for k in ('file','delta_lab_mean','delta_C_mean','delta_E76_mean','identical_rgb_fraction')} for r in rows]}, ensure_ascii=False, indent=2))
