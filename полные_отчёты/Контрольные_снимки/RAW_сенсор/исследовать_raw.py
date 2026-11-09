"""Read original RAF files and summarize one constant CFA phase, with no rendering.

Sample every 12 pixels in each dimension; 12 is a multiple of the 6x6 X-Trans
pattern. Summaries are not full-channel calibrated measurements. Sources are
opened read-only; only this directory's JSON is written.
"""
from pathlib import Path
import hashlib
import json
import numpy as np
import rawpy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / 'Тестовые фото'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

records = {}
for number in range(292, 300):
    path = SOURCE / f'DSCF{number:04d}.RAF'
    before = sha(path)
    st = path.stat()
    with rawpy.imread(str(path)) as raw:
        color = raw.raw_colors_visible[::12, ::12]
        assert np.all(color == color[0, 0]), 'sampling must select one CFA phase'
        channel = int(color[0, 0])
        black = int(raw.black_level_per_channel[channel])
        white = int(raw.white_level)
        samples = raw.raw_image_visible[::12, ::12].astype(np.float64)
        central = samples[samples.shape[0]//4:3*samples.shape[0]//4, samples.shape[1]//4:3*samples.shape[1]//4]
        record = {
            'source': path.name, 'sha256_before': before,
            'raw_dimensions_wh': [int(raw.sizes.raw_width), int(raw.sizes.raw_height)],
            'visible_dimensions_wh': [int(raw.sizes.width), int(raw.sizes.height)],
            'crop_left_top': [int(raw.sizes.left_margin), int(raw.sizes.top_margin)],
            'cfa_pattern': raw.raw_pattern.tolist() if raw.raw_pattern is not None else None,
            'color_desc_ascii': bytes(raw.color_desc).decode('ascii', errors='replace').rstrip('\x00'),
            'phase_top_left_color_index': channel, 'stride_yx': [12, 12],
            'sample_shape_hw': list(samples.shape), 'black_level': black, 'white_level': white,
            'sample_mean_raw': float(np.mean(samples)), 'sample_median_raw': float(np.median(samples)),
            'sample_mean_black_subtracted': float(np.mean(samples - black)),
            'central_mean_black_subtracted': float(np.mean(central - black)),
            'sample_percentiles_raw': {str(q): float(np.percentile(samples, q)) for q in [1, 5, 50, 95, 99]},
            'fraction_sample_greater_equal_white': float(np.mean(samples >= white)),
            'fraction_sample_greater_equal_99pct_white_above_black': float(np.mean(samples >= black + 0.99 * (white - black))),
        }
    after = sha(path)
    assert before == after and (st.st_size, st.st_mtime_ns) == (path.stat().st_size, path.stat().st_mtime_ns)
    record['sha256_after'] = after
    records[path.stem] = record

def group_mean(stems, field):
    return float(np.mean([records[f'DSCF{x:04d}'][field] for x in stems]))

groups = {'classic_0': [292, 295], 'classic_plus2': [293, 294], 'owner_recipe': [296, 297], 'reala_0': [298, 299]}
means = {label: {'stems': ids, 'whole_sample_black_subtracted': group_mean(ids, 'sample_mean_black_subtracted'),
                 'central_sample_black_subtracted': group_mean(ids, 'central_mean_black_subtracted')} for label, ids in groups.items()}
result = {'method': 'LibRaw/rawpy raw_image_visible, one common CFA phase every 12 pixels; black-subtracted sample means; no demosaic, white balance, tone or film simulation. No alignment or lens/sensor spectral calibration. Input order from owner, matched to chronological filenames subject to metadata check.',
          'limitations': ['single CFA phase, not rendered green or independent full spectral channel', 'global or central averages affected by geometry, lighting and scene changes', 'do not interpret as JPEG color or precise exposure calibration'],
          'records': records, 'groups': means}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'groups': means, 'sample_channel': {k: v['phase_top_left_color_index'] for k,v in records.items()},
                  'white_clipped_sample': {k: v['fraction_sample_greater_equal_white'] for k,v in records.items()}},ensure_ascii=False, indent=2))
