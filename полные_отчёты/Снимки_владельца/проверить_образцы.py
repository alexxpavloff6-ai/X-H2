"""Independently validate selected Fuji metadata and read two sensor mosaics.

Reads files only. Uses ExifRead as a second parser and rawpy/LibRaw for RAF.
"""
from pathlib import Path
import hashlib
import io
import json
import struct
import exifread
import rawpy

HERE=Path(__file__).resolve().parent
SOURCE=Path(r'<папка снимков владельца>')
SAMPLES={'DSCF9761':0x800,'DSCF9768':0xb00,'DSCF0001':0x600,'DSCF0291':0x600}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as s:
  while chunk:=s.read(1024*1024):h.update(chunk)
 return h.hexdigest()


def selected(t):
 return {'model':str(t.get('Image Model','')),'lens':str(t.get('EXIF LensModel','')),
         'taken':str(t.get('EXIF DateTimeOriginal','')),
         'film_tag_1401':int(str(t['MakerNote Tag 0x1401'])),
         'saturation':str(t.get('MakerNote Saturation',''))}


def main():
 output={}
 for stem,expected in SAMPLES.items():
  jpg=SOURCE/(stem+'.JPG');raf=SOURCE/(stem+'.RAF')
  before={p.name:(p.stat().st_size,p.stat().st_mtime_ns) for p in (jpg,raf)}
  with jpg.open('rb') as s:jpgmeta=selected(exifread.process_file(s,details=True))
  with raf.open('rb') as s:
   h=s.read(128);assert h[:16]==b'FUJIFILMCCD-RAW '
   off,size=struct.unpack_from('>II',h,84);assert off+size<=raf.stat().st_size
   s.seek(off);preview=s.read(size);assert len(preview)==size
  rafmeta=selected(exifread.process_file(io.BytesIO(preview),details=True))
  assert jpgmeta==rafmeta and jpgmeta['model']=='X-H2' and jpgmeta['film_tag_1401']==expected
  item={'jpg':jpgmeta,'raf_preview':rafmeta,'jpeg_sha256':sha(jpg),'raf_sha256':sha(raf)}
  if stem in ('DSCF9768','DSCF0001'):
   with rawpy.imread(str(raf)) as raw:
    item['sensor']={'raw_width':raw.sizes.raw_width,'raw_height':raw.sizes.raw_height,
                    'visible_width':raw.sizes.width,'visible_height':raw.sizes.height,
                    'cfa_pattern_rows':raw.raw_pattern.tolist(),'white_level':raw.white_level,
                    'visible_first_sample':int(raw.raw_image_visible[0,0])}
  assert all((p.stat().st_size,p.stat().st_mtime_ns)==before[p.name] for p in (jpg,raf))
  output[stem]=item
 (HERE/'Проверка_образцов.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'samples':{k:{'film_code':v['jpg']['film_tag_1401'],'model':v['jpg']['model'],'lens':v['jpg']['lens'],'raw_sensor_read': 'sensor' in v} for k,v in output.items()},'source_size_mtime_unchanged':True},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
