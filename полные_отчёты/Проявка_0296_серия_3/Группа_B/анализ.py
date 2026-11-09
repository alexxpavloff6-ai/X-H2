# -*- coding: utf-8 -*-
"""Исследование JPEG группы B. Python, numpy, opencv-python, Pillow, ExifTool и Perl.
Запуск: python -X utf8 путь/анализ.py [путь_к_RAF]. Данные только читаются.
"""
from pathlib import Path
import os, sys, json, hashlib, subprocess
import numpy as np
import cv2
from PIL import Image, JpegImagePlugin

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
B = ROOT / 'Тестовые фото/Доработка 296 в камере/Доработка 3/B'
A17 = B.parent / 'A/DSCF0317.JPG'
A18 = B.parent / 'A/DSCF0318.JPG'
RAW = Path(sys.argv[1]) if len(sys.argv)>1 else Path('<папка снимков владельца>')
EXIF = Path(os.environ['TEMP'])/'xh2metadata/exiftool-13.61/exiftool'
PERL = Path('C:/Program Files/Git/usr/bin/perl.exe')
CMD = [str(PERL), str(EXIF)]
paths={f'B{i}':B/f'DSCF{317+i:04d}.JPG' for i in range(1,6)}
paths.update({'A0317':A17,'A0318':A18})
if RAW.is_file(): paths['candidate_RAF']=RAW

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while chunk:=f.read(1024*1024): h.update(chunk)
    return h.hexdigest()

def exif(p, numeric=False):
    args=['-j','-G1','-a','-charset','UTF8']+(['-n'] if numeric else [])
    return json.loads(subprocess.run(CMD+args+['-'],input=p.read_bytes(),capture_output=True,check=True).stdout)[0]

def summary(x):
    x=np.asarray(x).ravel()
    if not x.size:return None
    return {'mean':float(np.mean(x,dtype=np.float64)),'median':float(np.median(x)), 'p95':float(np.percentile(x,95))}

def vector_stats(v,mask):
    x=v[mask]
    if not len(x):return None
    norm=np.linalg.norm(x,axis=1)
    return {'L':summary(x[:,0]),'a':summary(x[:,1]),'b':summary(x[:,2]),'norm':summary(norm), 'mean_vector_norm':float(np.linalg.norm(np.mean(x,axis=0,dtype=np.float64)))}

def lab(path,offset=0):
    with Image.open(path) as im: rgb=np.asarray(im.convert('RGB'))[offset::8,offset::8].copy()
    return cv2.cvtColor(rgb.astype(np.float32)/255,cv2.COLOR_RGB2LAB),rgb

before={k:sha(p) for k,p in paths.items()}
numeric={k:exif(p,True) for k,p in paths.items()}
text={k:exif(p) for k,p in paths.items() if k.startswith('B')}
# Curated photography fields only; no location, identity, file numbers, private values.
wanted=['Model','ImageWidth','ImageHeight','Quality','FilmMode','Saturation','HighlightTone','ShadowTone','WhiteBalance','WhiteBalanceFineTune','ColorTemperature','Clarity','Sharpness','NoiseReduction','ColorChromeEffect','ColorChromeFXBlue','DynamicRange','DynamicRangeSetting','GrainEffectRoughness','GrainEffectSize','LensModulationOptimizer','ColorSpace','ExposureTime','FNumber','ISO','FocalLength','ImageGeneration','WBRedLevel','WBGreenLevel','WBBlueLevel','Contrast','ExposureCompensation','FlashMode','BlurWarning']
def selected(d):return {k:v for k,v in d.items() if k.split(':')[-1] in wanted and not isinstance(v,(dict,list))}
fields={k:selected(numeric[k]) for k in numeric if k.startswith('B')}
keys=sorted(set().union(*(set(d) for d in fields.values())))
differences={key:{k:v.get(key) for k,v in fields.items()} for key in keys if len({json.dumps(v.get(key),sort_keys=True) for v in fields.values()})>1}
version=subprocess.run(CMD+['-ver'],capture_output=True,check=True,text=True).stdout.strip()
info={}
for k in [f'B{i}' for i in range(1,6)]:
    with Image.open(paths[k]) as im:
        q=im.quantization
        info[k]={'size':list(im.size),'mode':im.mode,'subsampling':JpegImagePlugin.get_sampling(im),'quantization_sha256':hashlib.sha256(json.dumps(q,sort_keys=True).encode()).hexdigest(),'icc_present':bool(im.info.get('icc_profile'))}

out={'method':{'inputs':'B1–B5 определены по паре числовых тегов 64/0; 64 = Strong, 0 = Off. Отдельно сохранены выбранные фототеги, а не идентификаторы.', 'color':'JPEG декодирован Pillow в RGB; при sRGB-теге без ICC RGB трактован как sRGB. OpenCV float32 RGB2Lab D65, C*=hypot(a*,b*), h=atan2(b*,a*) mod 360.', 'sampling':'Сетка каждого восьмого исходного пикселя, смещения 0 и 4, без ресемплинга; маски фиксированы по B1 на соответствующей сетке. Пиксели пространственно зависимы и не являются независимыми съёмками.', 'masks':'blue: 210≤h<310, C≥15, 15<L<85; warm: 0≤h<75, C≥15, 15<L<85; green: 75≤h<165, C≥15, 15<L<85; neutral: C<10, 15<L<85; all: все. Маски неполны и условны, пороги заданы до вычислений.', 'contrasts':'Эффекты Strong−Off: FX при Chrome Strong B1−B2 и Off B3−B4, Chrome при FX Strong B1−B3 и Off B2−B4, а также средние двух условных эффектов. Остаток I=B1−B2−B3+B4, альтернативный повтор I5=B5−B2−B3+B4. Единицы Lab; norm — попиксельная длина вектора, не знак эффекта. Сравнение остатков с повтором описательное, не статистический тест.', 'versions':{'exiftool':version,'opencv':cv2.__version__,'numpy':np.__version__}},'sha256_before':before,'jpeg':info,'selected_numeric_metadata':fields,'selected_metadata_differences':differences,'selected_readable_metadata':{k:selected(v) for k,v in text.items()},'grids':{}}
groups=('FujiFilm:', 'ExifIFD:', 'IFD0:')
all_keys=sorted(k for k in set().union(*(numeric[f'B{i}'].keys() for i in range(1,6))) if k.startswith(groups))
changed=[k for k in all_keys if len({json.dumps(numeric[f'B{i}'].get(k),sort_keys=True) for i in range(1,6)})>1]
out['all_known_camera_ifd_comparison']={'groups':list(groups),'count':len(all_keys),'different_tag_names':changed,'note':'Извлечённые известные теги без -u/-U; опубликованы лишь названия различающихся полей. Скрытые настройки не проверяются.'}

for off in [0,4]:
    l={}; rgb={}
    for k in [f'B{i}' for i in range(1,6)]: l[k],rgb[k]=lab(paths[k],off)
    base=l['B1']; C=np.hypot(base[:,:,1],base[:,:,2]); h=np.mod(np.degrees(np.arctan2(base[:,:,2],base[:,:,1])),360); valid=(base[:,:,0]>15)&(base[:,:,0]<85)
    masks={'all':np.ones(C.shape,dtype=bool),'blue':valid&(C>=15)&(h>=210)&(h<310),'warm':valid&(C>=15)&(h<75),'green':valid&(C>=15)&(h>=75)&(h<165),'neutral':valid&(C<10)}
    contrasts={'repeat_B5_minus_B1':l['B5']-l['B1'],'fx_at_chrome_strong':l['B1']-l['B2'],'fx_at_chrome_off':l['B3']-l['B4'],'chrome_at_fx_strong':l['B1']-l['B3'],'chrome_at_fx_off':l['B2']-l['B4']}
    chroma={k:np.hypot(v[:,:,1],v[:,:,2]) for k,v in l.items()}
    chroma_pairs={'repeat_B5_minus_B1':chroma['B5']-chroma['B1'], 'fx_at_chrome_strong':chroma['B1']-chroma['B2'], 'fx_at_chrome_off':chroma['B3']-chroma['B4'], 'chrome_at_fx_strong':chroma['B1']-chroma['B3'], 'chrome_at_fx_off':chroma['B2']-chroma['B4']}
    contrasts['fx_main_mean']=(contrasts['fx_at_chrome_strong']+contrasts['fx_at_chrome_off'])/2
    contrasts['chrome_main_mean']=(contrasts['chrome_at_fx_strong']+contrasts['chrome_at_fx_off'])/2
    contrasts['interaction']=l['B1']-l['B2']-l['B3']+l['B4']
    contrasts['interaction_using_repeat']=l['B5']-l['B2']-l['B3']+l['B4']
    gray=cv2.cvtColor(rgb['B1'],cv2.COLOR_RGB2GRAY).astype(np.float32)
    registration={}
    for k in ['B2','B3','B4','B5']:
        other=cv2.cvtColor(rgb[k],cv2.COLOR_RGB2GRAY).astype(np.float32)
        shift,response=cv2.phaseCorrelate(gray,other)
        registration[k]={'shift_grid_pixels':list(map(float,shift)),'response':float(response),'rgb_mae':float(np.mean(np.abs(rgb[k].astype(np.float32)-rgb['B1'].astype(np.float32))))}
    out['grids'][str(off)]={'shape':list(C.shape),'registration':registration,'masks':{name:{'n':int(mask.sum()),'fraction':float(mask.mean()),'base_L':summary(base[:,:,0][mask]),'base_C':summary(C[mask]),'contrasts':{key:vector_stats(value,mask) for key,value in contrasts.items()}} for name,mask in masks.items()}}
    for name,mask in masks.items():
        out['grids'][str(off)]['masks'][name]['chroma_pair_differences']={key:summary(value[mask]) for key,value in chroma_pairs.items()}
    del l,rgb,contrasts,chroma,chroma_pairs

# Candidate identity is a scene/technical match, not proof of RAW ancestry.
if 'candidate_RAF' in paths:
    preview=subprocess.run(CMD+['-b','-PreviewImage',str(RAW)],capture_output=True,check=True).stdout
    pic=cv2.imdecode(np.frombuffer(preview,dtype=np.uint8),cv2.IMREAD_GRAYSCALE)
    with Image.open(paths['B1']) as im:
        bgray=np.asarray(im.convert('L').resize((192,128)))
    if pic is None: raise RuntimeError('RAF PreviewImage отсутствует или не декодируется')
    small=cv2.resize(pic,(192,128),interpolation=cv2.INTER_AREA)
    out['candidate_RAF']={'basename':RAW.name,'preview_gray_correlation_192x128':float(np.corrcoef(bgray.ravel(),small.ravel())[0,1]),'selected_numeric_metadata':selected(numeric['candidate_RAF']),'caveat':'Сходство превью и теги не доказывают происхождение JPEG из этого RAW.'}
    check=['IFD0:Model','ExifIFD:DateTimeOriginal','ExifIFD:CreateDate','ExifIFD:ExposureTime','ExifIFD:FNumber','ExifIFD:ISO','ExifIFD:FocalLength','ExifIFD:LensModel']
    out['candidate_RAF']['matching_shooting_fields']={k:(numeric['candidate_RAF'].get(k)==numeric['B1'].get(k) if k in numeric['candidate_RAF'] and k in numeric['B1'] else None) for k in check}
# Scene distinction for file that was misplaced in A.
with Image.open(A17) as im: other=np.asarray(im.convert('L').resize((192,128)))
with Image.open(paths['B1']) as im: reference=np.asarray(im.convert('L').resize((192,128)))
out['A0317_vs_B1_gray_correlation']=float(np.corrcoef(other.ravel(),reference.ravel())[0,1])
out['sha256_after']={k:sha(p) for k,p in paths.items()}
out['inputs_unchanged']=before==out['sha256_after']
if not out['inputs_unchanged']:raise RuntimeError('Вход изменился; результат не записан')
(HERE/'результат.json').write_text(json.dumps(out,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
print('Результаты записаны; хеши входов до и после совпали.')
