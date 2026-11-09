"""Read-only verification of proposed RAF/JPEG pairs, without exporting photos or private EXIF."""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RAW_DIR = Path(r'<папка снимков владельца>')
JPG_DIR = ROOT / 'Тестовые фото/Доработка 296 в камере/Доработка 3'
EXIF = Path(os.environ.get('TEMP', os.environ.get('TMP', ''))) / 'xh2metadata/exiftool-13.61/exiftool'
PERL = Path('C:/Program Files/Git/usr/bin/perl.exe')
PAIRS = [('DSCF9835.RAF', 'B/DSCF0318.JPG'), ('DSCF0064.RAF', 'A/DSCF0317.JPG')]
TAGS = ('Model', 'DateTimeOriginal', 'CreateDate', 'ExposureTime', 'FNumber', 'ISO', 'FocalLength', 'LensModel', 'ImageGeneration')

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(1024*1024), b''): h.update(data)
    return h.hexdigest()

def metadata(path):
    cmd=[str(PERL),str(EXIF),'-j','-n','-G1', *['-'+tag for tag in TAGS], '-']
    with path.open('rb') as f:
        data=subprocess.run(cmd,input=f.read(),capture_output=True,check=True).stdout
    return json.loads(data)[0]

def thumb(buf):
    img=cv2.imdecode(np.frombuffer(buf,dtype=np.uint8),cv2.IMREAD_REDUCED_GRAYSCALE_8)
    if img is None: raise ValueError('JPEG preview cannot be decoded')
    img=cv2.resize(img,(192,128),interpolation=cv2.INTER_AREA).astype(np.float32).ravel()
    img -= img.mean()
    norm=float(np.linalg.norm(img))
    if norm == 0: raise ValueError('Flat grayscale image')
    return img/norm

def raw_preview(path):
    size=path.stat().st_size
    with path.open('rb') as f:
        if f.read(16)!=b'FUJIFILMCCD-RAW ': raise ValueError('Unknown RAF signature')
        f.seek(84); offset,length=struct.unpack('>II',f.read(8))
        if not 0<offset<size or not 0<length<=10_000_000 or offset+length>size: raise ValueError('Invalid embedded preview bounds')
        f.seek(offset); return f.read(length)

results=[]
for raw_name,jpeg_rel in PAIRS:
    raw,jpeg=RAW_DIR/raw_name,JPG_DIR/jpeg_rel
    before={'raw':digest(raw),'jpeg':digest(jpeg)}
    comparison=float(thumb(raw_preview(raw)) @ thumb(jpeg.read_bytes()))
    a,b=metadata(raw),metadata(jpeg)
    keys=sorted((set(a)&set(b)) - {'SourceFile','FujiFilm:ImageGeneration'})
    equality={k: a[k]==b[k] for k in keys}
    after={'raw':digest(raw),'jpeg':digest(jpeg)}
    if before!=after: raise RuntimeError('Source changed while analyzing')
    results.append({'raw_name':raw_name,'jpeg':jpeg_rel,'embedded_preview_grayscale_correlation':comparison,
                    'selected_exif_field_equality':equality,
                    'raw_generation':a.get('FujiFilm:ImageGeneration'), 'jpeg_generation':b.get('FujiFilm:ImageGeneration'),
                    'sha256_before_after':before})
output={'method':'Compare embedded RAF JPEG preview with decoded camera JPEG: OpenCV 1/8 grayscale decode resized 192x128 then Pearson correlation; independently compare selected ExifTool -n fields by equality only. Similarity and EXIF support but do not prove pixel origin. RAW previews are not new independent captures. No photos, precise times, GPS or serial numbers exported.',
        'pairs':results,'opencv_version':cv2.__version__}
(HERE/'результат.json').write_text(json.dumps(output,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
print(json.dumps(results,ensure_ascii=False,indent=2))
