"""Test a deliberately simple Lab-space gain hypothesis on camera JPEGs.
This is not a reconstruction of the Fuji ISP or an assertion of its color space.
"""
from pathlib import Path
import hashlib
import json
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
source = ROOT / 'Тестовые фото/Доработка 296 в камере'

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

images, hashes = {}, {}
for n in (300, 301, 302):
    p = source / f'DSCF{n:04d}.JPG'
    before = sha(p)
    im = cv2.imdecode(np.fromfile(p, dtype=np.uint8), cv2.IMREAD_COLOR)
    if im is None or im.shape != (5152, 7728, 3):
        raise ValueError(f'Unexpected JPEG: {p.name}')
    images[n] = cv2.resize(im, (966, 644), interpolation=cv2.INTER_AREA)
    del im
    assert sha(p) == before
    hashes[p.name] = before
lab = {n: cv2.cvtColor(im.astype(np.float32) / 255, cv2.COLOR_BGR2LAB) for n, im in images.items()}
c0 = np.hypot(lab[301][:, :, 1], lab[301][:, :, 2])
mask = np.ones((644, 966), dtype=bool)
for im in images.values():
    mask &= np.all((im > 5) & (im < 250), axis=2)
mask &= (lab[301][:, :, 0] > 15) & (lab[301][:, :, 0] < 85) & (c0 > 10)
ref = lab[301][:, :, 1:3][mask]
if not len(ref):
    raise ValueError('No pixels selected')
rows = []
for n, gain in ((300, 134 / 128), (302, 141 / 128)):
    actual = lab[n][:, :, 1:3][mask]
    predicted = gain * ref
    residual = np.linalg.norm(actual - predicted, axis=1)
    no_change = np.linalg.norm(actual - ref, axis=1)
    rows.append({'target': f'DSCF{n:04d}.JPG', 'hypothetical_gain': gain,
                 'residual_mean_ab': float(residual.mean()), 'residual_median_ab': float(np.median(residual)),
                 'residual_p90_ab': float(np.percentile(residual, 90)),
                 'residual_fraction_ab_gt1': float(np.mean(residual > 1)),
                 'no_change_mean_ab': float(no_change.mean()),
                 'no_change_median_ab': float(np.median(no_change))})
result = {'method': 'Exploratory hypothesis only: apply g to a*,b* of the reduced decoded sRGB Lab reference; compare to actual a*,b* at same coordinates, ignoring L*. g=134/128 or 141/128 comes from a previous synthetic Classic Chrome coefficient calculation, not a measured ISP mapping. All RGB channels of all three reduced JPEGs in 6..249, reference L* 15..85 and C*>10. One scene, no registration, no independent validation, JPEG and Lab nonlinearities included.',
          'source_sha256': hashes, 'opencv_version': cv2.__version__, 'numpy_version': np.__version__,
          'mask_fraction': float(mask.mean()), 'mask_pixels': int(mask.sum()), 'comparisons': rows}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'mask_fraction': result['mask_fraction'], 'mask_pixels': result['mask_pixels'], 'comparisons': rows}, ensure_ascii=False, indent=2))
