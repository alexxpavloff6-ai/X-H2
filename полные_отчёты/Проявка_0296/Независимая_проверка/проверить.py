"""Сравнение трёх JPEG одного RAW. Только чтение источников, без публикации сцены."""
from pathlib import Path
import hashlib
import json
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / 'Тестовые фото' / 'Доработка 296 в камере'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


images = {}
hashes = {}
for n in (300, 301, 302):
    path = SOURCE / f'DSCF{n:04d}.JPG'
    before = sha(path)
    img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f'JPEG не декодирован: {path.name}')
    assert img.shape == (5152, 7728, 3)
    images[n] = cv2.resize(img, (966, 644), interpolation=cv2.INTER_AREA)
    del img
    after = sha(path)
    assert after == before
    hashes[path.name] = before

# OpenCV float BGR2Lab expects sRGB. Camera EXIF says sRGB, no ICC attached.
lab = {n: cv2.cvtColor(a.astype(np.float32) / 255, cv2.COLOR_BGR2LAB) for n, a in images.items()}
chroma = {n: np.hypot(a[:, :, 1], a[:, :, 2]) for n, a in lab.items()}
mask = np.ones((644, 966), dtype=bool)
for a in images.values():
    mask &= np.all((a > 5) & (a < 250), axis=2)
mask &= (lab[301][:, :, 0] > 15) & (lab[301][:, :, 0] < 85) & (chroma[301] > 3)
assert mask.any()
comparisons = []
for a, b in ((301, 300), (300, 302), (301, 302)):
    dc = (chroma[b] - chroma[a])[mask]
    dl = (lab[b][:, :, 0] - lab[a][:, :, 0])[mask]
    ratio = chroma[b][mask] / chroma[a][mask]
    assert np.all(np.isfinite(ratio))
    comparisons.append({'from': f'DSCF{a:04d}', 'to': f'DSCF{b:04d}',
                        'median_delta_Cab': float(np.median(dc)), 'mean_delta_Cab': float(np.mean(dc)),
                        'fraction_delta_Cab_positive': float(np.mean(dc > 0)),
                        'delta_Cab_p10_p90': [float(v) for v in np.percentile(dc, [10, 90])],
                        'median_Cab_ratio': float(np.median(ratio)),
                        'Cab_ratio_p10_p90': [float(v) for v in np.percentile(ratio, [10, 90])],
                        'median_delta_L': float(np.median(dl))})
bin_metrics = []
for name, values, low, high in (
    ('L 15..35', lab[301][:, :, 0], 15, 35),
    ('L 35..55', lab[301][:, :, 0], 35, 55),
    ('L 55..85', lab[301][:, :, 0], 55, 85),
    ('C 3..10', chroma[301], 3, 10),
    ('C 10..20', chroma[301], 10, 20),
    ('C 20..40', chroma[301], 20, 40),
    ('C 40+', chroma[301], 40, float('inf')),
):
    subset = mask & (values >= low) & (values < high)
    r = chroma[302][subset] / chroma[301][subset]
    assert r.size and np.all(np.isfinite(r))
    bin_metrics.append({'bin': name, 'pixels': int(r.size), 'median_Cab_ratio_2_vs_0': float(np.median(r))})
output = {'method': 'CV2 JPEG BGR -> 966x644 INTER_AREA -> float sRGB Lab. Same coordinates, no geometric registration. Common mask: all RGB channels 6..249 in all three frames; reference 0301 L* 15..85, C*ab >3. C* difference is not percent or ISP coefficient. User identifies all as camera developments of same RAF; image content/dimensions must not be assumed equal in other experiments.',
          'sample_fraction': float(np.mean(mask)), 'source_sha256': hashes,
          'opencv_version': cv2.__version__, 'numpy_version': np.__version__, 'comparisons': comparisons,
          'ratio_2_vs_0_by_reference_bin': bin_metrics}
(HERE / 'результаты.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'sample_fraction': output['sample_fraction'], 'comparisons': comparisons}, ensure_ascii=False, indent=2))
