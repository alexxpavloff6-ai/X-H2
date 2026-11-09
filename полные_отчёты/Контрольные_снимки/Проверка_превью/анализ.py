#!/usr/bin/env python3
"""Сравнение только агрегатов, без сохранения изображений; см. Отчёт.md."""
import importlib.util
import itertools
import json
import platform
import sys
from pathlib import Path

import cv2
import numpy as np
import PIL

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('color_analysis', HERE.parent / 'Цвет' / 'анализ.py')
color = importlib.util.module_from_spec(spec)
spec.loader.exec_module(color)
if len(sys.argv) > 1:
    color.SOURCE = Path(sys.argv[1])

ids = color.JPG_IDS
imgs = {}
for i in color.IDS:
    for kind in (('RAF', 'JPG') if i in ids else ('RAF',)):
        imgs[i, kind], _ = color.image_data(i, kind)

same = {str(i): color.comparison(imgs[i, 'JPG'], imgs[i, 'RAF']) for i in ids}
pairs = {}
for a, b in itertools.combinations(ids, 2):
    pairs[f'{a}-{b}'] = {kind: color.comparison(imgs[a, kind], imgs[b, kind]) for kind in ('JPG', 'RAF')}

# The same procedure applied to the recipe frames and neighboring controls.
recipe = {}
for a, b in ((295, 296), (295, 297), (296, 297), (296, 298), (297, 298), (296, 299), (297, 299)):
    recipe[f'{a}-{b}'] = color.comparison(imgs[a, 'RAF'], imgs[b, 'RAF'])

summary = {}
for mask in ('overlap', 'unclipped', 'unclipped_Lmatched'):
    summary[mask] = {}
    for metric in ('delta_Lstar_median', 'delta_chroma_median', 'delta_a_median', 'delta_b_median', 'deltaE76_median', 'deltaE76_p90'):
        vals = [(v['JPG']['masks'][mask][metric], v['RAF']['masks'][mask][metric]) for v in pairs.values()]
        diffs = np.array([r-j for j, r in vals])
        signs = int(sum(np.sign(j) == np.sign(r) for j, r in vals)) if metric.startswith('delta_') else None
        summary[mask][metric] = {'max_abs_preview_minus_jpg': float(np.max(np.abs(diffs))),
                                 'median_abs_preview_minus_jpg': float(np.median(np.abs(diffs))),
                                 'same_sign_count': signs, 'pair_count': len(vals)}

out = {'method': {'working_size': list(color.SIZE), 'direction': 'second frame minus first frame',
                  'registration': 'independent affine ECC on grayscale per comparison, linear interpolation',
                  'masks': 'See ../Цвет/анализ.py: overlap, RGB guard, guard with |ΔL*| ≤ 3 and reference L* 15–85',
                  'lab': 'OpenCV float RGB to Lab, treating JPEG RGB as sRGB',
                  'comparison': 'all 15 cross-frame pairs of six available JPGs; repeat identically using corresponding RAF previews; independently registered and independently masked',
                  'source_images_saved': False,
                  'versions': {'python': platform.python_version(), 'opencv': cv2.__version__, 'numpy': np.__version__, 'pillow': PIL.__version__}},
       'same_frame_jpg_to_preview': same, 'cross_frame_jpg_and_preview': pairs,
       'cross_frame_summary': summary, 'recipe_preview_pairs': recipe}
(HERE / 'результаты.json').write_text(json.dumps(out, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
print('Готово:', HERE / 'результаты.json')
