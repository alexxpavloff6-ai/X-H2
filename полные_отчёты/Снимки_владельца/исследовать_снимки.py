"""Read Fuji RAF previews and matching JPEG metadata without changing originals.

Fuji MakerNote tag meanings follow https://exiftool.org/TagNames/FujiFilm.html.
Pairing is by file stem and matching metadata. JPEG files were processed in
Lightroom according to their owner; copied metadata do not prove rendering.
No GPS or serial numbers are exported.
"""
from pathlib import Path
from PIL import Image
import collections
import csv
import io
import json
import struct

SOURCE=Path(r'<папка снимков владельца>')
HERE=Path(__file__).resolve().parent
FILM={0x000:'Provia/Standard',0x100:'F1/Studio Portrait',0x110:'F1a',0x120:'Astia',0x130:'F1c',0x200:'Velvia',0x300:'F3',0x400:'F4/Velvia',0x500:'Pro Neg. Std',0x501:'Pro Neg. Hi',0x600:'Classic Chrome',0x700:'Eterna',0x800:'Classic Negative',0x900:'Eterna Bleach Bypass',0xa00:'Nostalgic Neg.',0xb00:'Reala ACE'}
TYPES={1:1,2:1,3:2,4:4,5:8,7:1,9:4,10:8}


def fuji_note(data):
 if not isinstance(data,bytes) or data[:8]!=b'FUJIFILM':raise ValueError('Missing Fuji MakerNote')
 off=struct.unpack_from('<I',data,8)[0]
 if off+2>len(data):raise ValueError('Invalid MakerNote directory')
 count=struct.unpack_from('<H',data,off)[0]
 if count>2048 or off+2+12*count>len(data):raise ValueError('Invalid MakerNote entry count')
 out={}
 for i in range(count):
  pos=off+2+12*i;tag,typ,n=struct.unpack_from('<HHI',data,pos)
  if typ not in TYPES or n>100000:continue
  length=TYPES[typ]*n;location=pos+8 if length<=4 else struct.unpack_from('<I',data,pos+8)[0]
  if location+length>len(data):raise ValueError(f'Invalid MakerNote value 0x{tag:04x}')
  if typ in (3,4,9):
   fmt={3:'H',4:'I',9:'i'}[typ];value=struct.unpack_from('<'+str(n)+fmt,data,location);out[tag]=value[0] if n==1 else list(value)
  elif typ==2:out[tag]=data[location:location+length].split(b'\0',1)[0].decode('ascii','replace').strip()
 return out


def text(v):return str(v).replace('\x00','').strip() if v is not None else ''


def extract(image):
 with Image.open(image) as im:
  ex=im.getexif();sub=ex.get_ifd(0x8769);maker=fuji_note(sub.get(0x927c))
  film=maker.get(0x1401)
  return {'model':text(ex.get(0x110)),'software':text(ex.get(0x131)),'taken':text(sub.get(0x9003)),
    'lens':text(sub.get(0xa434)),'focal_mm':text(sub.get(0x920a)),'aperture':text(sub.get(0x829d)),
    'shutter':text(sub.get(0x829a)),'iso':text(sub.get(0x8827)),
    'film_raw':film,'film_name':FILM.get(film,('Unknown '+hex(film)) if isinstance(film,int) else 'Not recorded'),
    'saturation_raw':maker.get(0x1003),'white_balance_raw':maker.get(0x1002),
    'wb_fine_tune_raw':maker.get(0x100a),'highlight_raw':maker.get(0x1041),
    'shadow_raw':maker.get(0x1040),'sharpness_raw':maker.get(0x1001),
    'noise_reduction_raw':maker.get(0x100e),'clarity_raw':maker.get(0x100f),
    'color_chrome_raw':maker.get(0x1048),'color_chrome_blue_raw':maker.get(0x104e),
    'grain_roughness_raw':maker.get(0x1047),'grain_size_raw':maker.get(0x104c),
    'dynamic_range_setting_raw':maker.get(0x1402),'color_temperature_raw':maker.get(0x1005),
    'generation_raw':maker.get(0x1436),'focus_mode_raw':maker.get(0x1021),'focus_settings_raw':maker.get(0x102d)}


def inspect_raf(path):
 with path.open('rb') as stream:
  h=stream.read(128)
  if len(h)<108 or h[:16]!=b'FUJIFILMCCD-RAW ':raise ValueError('Invalid RAF header')
  offset,size=struct.unpack_from('>II',h,84);total=path.stat().st_size
  if offset<128 or size<100 or offset+size>total or size>30*1024*1024:raise ValueError('Invalid RAF embedded preview bounds')
  stream.seek(offset);preview=stream.read(size)
  if len(preview)!=size or preview[:2]!=b'\xff\xd8':raise ValueError('Invalid RAF embedded JPEG')
  meta=extract(io.BytesIO(preview));meta['raf_preview_offset']=offset;meta['raf_preview_bytes']=size
  meta['raf_header_model']=h[28:60].split(b'\0',1)[0].decode('ascii','replace').strip()
  meta['raf_header_version']=h[60:64].decode('ascii','replace')
  return meta


def stat(path):
 s=path.stat();return s.st_size,s.st_mtime_ns


def main():
 if not SOURCE.is_dir():raise FileNotFoundError(SOURCE)
 files=[x for x in SOURCE.iterdir() if x.is_file()];raws={x.stem:x for x in files if x.suffix.lower()=='.raf'};jpgs={x.stem:x for x in files if x.suffix.lower() in ('.jpg','.jpeg')}
 rows=[];issues=[];compared=['model','taken','lens','film_raw','focal_mm','aperture','shutter','iso','saturation_raw','white_balance_raw']
 recipe_fields=['film_raw','saturation_raw','white_balance_raw','wb_fine_tune_raw','highlight_raw','shadow_raw','sharpness_raw','noise_reduction_raw','clarity_raw','color_chrome_raw','color_chrome_blue_raw','grain_roughness_raw','grain_size_raw','dynamic_range_setting_raw','color_temperature_raw']
 for stem in sorted(set(raws)|set(jpgs)):
  row={'stem':stem,'raf_file':raws[stem].name if stem in raws else '', 'jpg_file':jpgs[stem].name if stem in jpgs else ''}
  metas={}
  for kind,fileset in [('raf',raws),('jpg',jpgs)]:
   if stem not in fileset:continue
   path=fileset[stem]
   try:
    before=stat(path);meta=inspect_raf(path) if kind=='raf' else extract(path)
    if stat(path)!=before:raise ValueError('Source size or modification time changed')
    metas[kind]=meta
   except Exception as exc:issues.append({'file':path.name,'error':f'{type(exc).__name__}: {exc}'})
  preferred=metas.get('raf') or metas.get('jpg') or {}
  row.update(preferred)
  mismatches=[key for key in compared if key in metas.get('raf',{}) and key in metas.get('jpg',{}) and metas['raf'][key]!=metas['jpg'][key]]
  row['pair_status']='metadata_mismatch' if mismatches else ('metadata_match' if len(metas)==2 else ('single' if len(metas)==1 else 'unreadable'))
  row['pair_differences']=','.join(mismatches)
  row['recipe_differences']=','.join(key for key in recipe_fields if len(metas)==2 and metas['raf'].get(key)!=metas['jpg'].get(key))
  row['recipe_metadata_origin']='RAF embedded JPEG' if 'raf' in metas else ('Lightroom-processed JPEG metadata' if 'jpg' in metas else '')
  row['jpg_film_name']=metas.get('jpg',{}).get('film_name','')
  row['raf_film_name']=metas.get('raf',{}).get('film_name','')
  rows.append(row)
 fields=['stem','raf_file','jpg_file','model','software','taken','lens','focal_mm','aperture','shutter','iso','film_raw','film_name','saturation_raw','white_balance_raw','wb_fine_tune_raw','highlight_raw','shadow_raw','sharpness_raw','noise_reduction_raw','clarity_raw','color_chrome_raw','color_chrome_blue_raw','grain_roughness_raw','grain_size_raw','dynamic_range_setting_raw','color_temperature_raw','generation_raw','focus_mode_raw','focus_settings_raw','pair_status','pair_differences','recipe_differences','recipe_metadata_origin','raf_film_name','jpg_film_name','raf_header_model','raf_header_version','raf_preview_offset','raf_preview_bytes']
 with (HERE/'Каталог_снимков.tsv').open('w',encoding='utf-8-sig',newline='') as out:
  writer=csv.DictWriter(out,fields,delimiter='\t',extrasaction='ignore',lineterminator='\n');writer.writeheader();writer.writerows(rows)
 def counts(key,subset=rows):return dict(collections.Counter(str(r.get(key,'')) for r in subset))
 reala=[r for r in rows if r.get('film_raw')==0xb00]
 raw_rows=[r for r in rows if r['recipe_metadata_origin']=='RAF embedded JPEG']
 recipe_groups=[]
 for film in sorted({r.get('film_name','') for r in raw_rows}):
  selected=[r for r in raw_rows if r.get('film_name')==film]
  grouped=collections.Counter(tuple(json.dumps(r.get(key),ensure_ascii=False) for key in recipe_fields) for r in selected)
  recipe_groups.append({'base_film':film,'raf_count':len(selected),'tag_groups':[{'count':n,'tags':{key:json.loads(v) for key,v in zip(recipe_fields,values)}} for values,n in grouped.most_common()]})
 summary={'raf_files':len(raws),'jpg_files':len(jpgs),'image_stems':len(rows),'raf_without_jpg':sorted(set(raws)-set(jpgs)),'jpg_without_raf':sorted(set(jpgs)-set(raws)),
 'models':counts('model'),'software':counts('software'),'lenses':counts('lens'),'films':counts('film_name'),'film_raw':counts('film_raw'),'pair_status':counts('pair_status'),
 'reala_filenames':[r['stem'] for r in reala], 'reala_count':len(reala),'reala_lenses':counts('lens',reala),'saturation_raw':counts('saturation_raw'),
 'mismatched_pairs':[{'stem':r['stem'],'differences':r['pair_differences'],'raf_film':r['raf_film_name'],'jpg_film':r['jpg_film_name']} for r in rows if r['pair_status']=='metadata_mismatch'],
 'recipe_groups_raf':recipe_groups,'recipe_fields':recipe_fields,'recipe_metadata_mismatch_count':sum(bool(r['recipe_differences']) for r in rows),
 'issues':issues,'limitations':['Owner states JPEGs are Lightroom-processed; camera software metadata and matching tags do not prove in-camera rendering','FilmMode identifies base simulation, not a complete recipe or saved C-slot','Matching RAW/JPEG metadata can be inherited and are not independent rendering evidence','RAF preview JPEG metadata, not raw sensor samples or confirmed complete camera settings','No original is written; per-file size and modification time checked, not full file checksum','No GPS or serial numbers exported']}
 (HERE/'Итоги.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({k:v for k,v in summary.items() if k not in ('reala_filenames','mismatched_pairs','issues')},ensure_ascii=False,indent=2));print('issues',len(issues),'mismatched_pairs',len(summary['mismatched_pairs']))

if __name__=='__main__':main()
