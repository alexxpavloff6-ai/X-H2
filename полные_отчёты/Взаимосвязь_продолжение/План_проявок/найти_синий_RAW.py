"""Rank RAF files by blue/warm preview coverage. No images or private metadata saved.
Embedded previews are only a scene selection aid, not new camera developments.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
DEFAULT = Path(r'<папка снимков владельца>')
ap = argparse.ArgumentParser()
ap.add_argument('--raw-dir', type=Path, default=DEFAULT)
args = ap.parse_args()
files = sorted(args.raw_dir.glob('*.RAF'))
if not files:
    raise ValueError('No RAF files in supplied directory')
results, failures = [], []
for path in files:
    before = path.stat()
    try:
        with path.open('rb') as f:
            if f.read(16) != b'FUJIFILMCCD-RAW ':
                raise ValueError('RAF signature')
            f.seek(84)
            offset, length = struct.unpack('>II', f.read(8))
            if not 0 < offset < before.st_size or not 0 < length <= 10_000_000 or offset + length > before.st_size:
                raise ValueError('Invalid preview range')
            f.seek(offset)
            preview = f.read(length)
        image = cv2.imdecode(np.frombuffer(preview, dtype=np.uint8), cv2.IMREAD_REDUCED_COLOR_8)
        if image is None:
            raise ValueError('Preview not decoded')
        lab = cv2.cvtColor(image.astype(np.float32) / 255, cv2.COLOR_BGR2LAB)
        light, a, b = lab[:,:,0], lab[:,:,1], lab[:,:,2]
        chroma = np.hypot(a, b)
        hue = np.mod(np.degrees(np.arctan2(b, a)), 360)
        common = (chroma >= 15) & (light > 15) & (light < 85)
        blue = common & (hue >= 210) & (hue < 310)
        warm = common & (hue >= 0) & (hue < 75)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('Source changed while reading preview')
        results.append({'file':path.name, 'blue_fraction':float(blue.mean()), 'warm_fraction':float(warm.mean()), 'selection_score_minimum':float(min(blue.mean(),warm.mean()))})
    except Exception as exc:
        failures.append({'file':path.name, 'error_type':type(exc).__name__})
ranked = sorted(results, key=lambda r: r['selection_score_minimum'], reverse=True)
if not ranked:
    raise RuntimeError('No readable RAF preview')
candidate = args.raw_dir / ranked[0]['file']
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024), b''):
            h.update(part)
    return h.hexdigest()
digest1, digest2 = sha(candidate), sha(candidate)
if digest1 != digest2:
    raise RuntimeError('Candidate changed between full hash reads')
result = {'method':'Embedded JPEG only; OpenCV 1/8 reduced decode, assumed sRGB to Lab; blue hue [210,310), warm [0,75), C*>=15, 15<L*<85. Rank by min(blue,warm) coverage. Other raw files checked via stat during preview read, not full hashes; selected RAF full SHA read twice after ranking. Preview is not a direct camera development and cannot predict exact FX Blue effect. RAW must also be accessible to camera for conversion.',
          'count':len(files),'successful':len(results),'failures':failures,'top_candidates':ranked[:10],
          'selected_source_sha256_twice':digest1, 'opencv_version':cv2.__version__, 'numpy_version':np.__version__}
(HERE/'подбор_RAW.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'count':result['count'],'successful':result['successful'],'failures':len(failures),'top_candidates':ranked[:3]},ensure_ascii=False,indent=2))
