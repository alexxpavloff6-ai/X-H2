#!/usr/bin/env python3
"""Исследование исходных пикселей; запуск из любого каталога: python анализ.py.
Зависимости: numpy, Pillow, opencv-python; ExifTool 13.61 и Perl для метаданных.
Никакие изображения и полные EXIF не сохраняются.
"""
from pathlib import Path
import os, hashlib, json, subprocess, argparse
import numpy as np
import cv2
from PIL import Image

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'Тестовые фото' / 'Доработка 296 в камере'
FILES = [BASE / 'DSCF0300.JPG'] + [BASE / 'Доработка 2' / f'DSCF{i:04d}.JPG' for i in (308,309,310)]
OUT = Path(__file__).with_name('результат.json')
FIELDS = ['ImageGeneration','Quality','FilmMode','Saturation','HighlightTone','ShadowTone','ColorChromeEffect','ColorChromeFXBlue','ColorTemperature','WhiteBalanceFineTune','Clarity','Sharpness','NoiseReduction','GrainEffect','DevelopmentDynamicRange']

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while b:=f.read(1024*1024): h.update(b)
    return h.hexdigest()

def dqt(path):
    data=path.read_bytes(); pos=2; chunks=[]
    if data[:2] != b'\xff\xd8': raise ValueError('Не JPEG')
    while pos < len(data):
        if data[pos] != 255: raise ValueError('Неверный маркер JPEG')
        while data[pos] == 255: pos+=1
        marker=data[pos]; pos+=1
        if marker in (0xda,0xd9): break
        if marker==1 or 0xd0<=marker<=0xd7: continue
        length=int.from_bytes(data[pos:pos+2], 'big')
        if length<2 or pos+length>len(data): raise ValueError('Неверная длина сегмента')
        if marker==0xdb: chunks.append(hashlib.sha256(data[pos+2:pos+length]).hexdigest())
        pos+=length
    return chunks

def metadata(path, cmd):
    flags=['-j','-G1','-a','-n']+['-'+s for s in FIELDS]+['-']
    p=subprocess.run(cmd+flags,input=path.read_bytes(),capture_output=True,check=True)
    row=json.loads(p.stdout)[0]
    return {k:v for k,v in row.items() if ':' in k and k.split(':')[-1] in FIELDS}

def metrics(y):
    # Crop 8 pixels to exclude filter boundaries. Values use 8-bit gamma-encoded Y'.
    sl=np.s_[8:-8,8:-8]
    mu=cv2.boxFilter(y,-1,(5,5),normalize=True)
    variance=np.maximum(cv2.boxFilter(y*y,-1,(5,5),normalize=True)-mu*mu,0)
    gx=cv2.Sobel(y,cv2.CV_32F,1,0,ksize=3,scale=1/8)
    gy=cv2.Sobel(y,cv2.CV_32F,0,1,ksize=3,scale=1/8)
    resid=y-cv2.GaussianBlur(y,(0,0),1.0)
    lap=cv2.Laplacian(y,cv2.CV_32F,ksize=1)
    # Pixel-level bright/dark content is not used to select the class.
    return {'mean_y':float(y[sl].mean()), 'local_sd_5':float(np.sqrt(variance[sl]).mean()),
            'gradient_rms':float(np.sqrt(np.mean(gx[sl]**2+gy[sl]**2))),
            'gaussian_residual_rms':float(np.sqrt(np.mean(resid[sl]**2))),
            'laplacian_rms':float(np.sqrt(np.mean(lap[sl]**2)))}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--exiftool',default=str(Path(os.environ.get('TEMP',os.environ.get('TMP',''))) / 'xh2metadata/exiftool-13.61/exiftool'))
    ap.add_argument('--perl',default='C:/Program Files/Git/usr/bin/perl.exe')
    args=ap.parse_args(); cmd=[args.perl,args.exiftool]
    before={p.name:sha(p) for p in FILES}
    version=subprocess.run(cmd+['-ver'],capture_output=True,text=True,check=True).stdout.strip()
    md={p.name:metadata(p,cmd) for p in FILES}
    tables={p.name:dqt(p) for p in FILES}
    images=[]
    for p in FILES:
        im=Image.open(p)
        if im.size != (7728,5152) or im.getexif().get(274,1)!=1: raise ValueError('Неожиданный размер или ориентация')
        a=np.asarray(im.convert('RGB'),dtype=np.float32)
        images.append(a[:,:,0]*.2126+a[:,:,1]*.7152+a[:,:,2]*.0722)
        del a
    # 12x8 regularly spaced centers, 256x256 pixels, no resize. Same fixed coordinates for every file.
    h,w=images[0].shape; patches=[]
    for iy in range(8):
        for ix in range(12):
            x=int((ix+.5)*w/12); y=int((iy+.5)*h/8)
            areas=[im[y-128:y+128,x-128:x+128] for im in images]
            ms=[metrics(a) for a in areas]
            registration=[]
            for a in areas[1:]:
                shift,response=cv2.phaseCorrelate(areas[0],a,cv2.createHanningWindow((256,256),cv2.CV_32F))
                registration.append({'shift_px':[float(v) for v in shift],'response':float(response)})
            patches.append({'grid':[ix,iy],'box_xyxy':[x-128,y-128,x+128,y+128],'metrics':ms,'registration':registration})
    # Fixed luminance bins and per-bin quantiles computed once using baseline only.
    # Bottom/top third gradient classify smooth/textured; bins and masks shared by all JPEGs.
    bins=[(0,64),(64,128),(128,192),(192,256)]
    keys=['local_sd_5','gradient_rms','gaussian_residual_rms','laplacian_rms']
    groups={}
    for lo,hi in bins:
        items=[p for p in patches if lo<=p['metrics'][0]['mean_y']<hi]
        if not items: continue
        q=np.quantile([p['metrics'][0]['gradient_rms'] for p in items],[1/3,2/3])
        for group in ('smooth','textured'):
            selected=[p for p in items if (p['metrics'][0]['gradient_rms']<=q[0] if group=='smooth' else p['metrics'][0]['gradient_rms']>=q[1])]
            summary={}
            for k in keys:
                base=np.array([p['metrics'][0][k] for p in selected])
                summary[k]={}
                for j,pth in enumerate(FILES[1:],1):
                    v=np.array([p['metrics'][j][k] for p in selected]); delta=v-base
                    summary[k][pth.name]={'base_mean':float(base.mean()),'image_mean':float(v.mean()),'change_of_means_percent':float((v.mean()/base.mean()-1)*100) if base.mean() else None,'median_paired_delta':float(np.median(delta)),'patches_increase':int((delta>0).sum()),'patches_decrease':int((delta<0).sum())}
            groups[f'{lo}-{hi}_{group}']={'n':len(selected),'baseline_gradient_thresholds':q.tolist(),'grid_members':[p['grid'] for p in selected],'metrics':summary}
    shifts={}
    for j,p in enumerate(FILES[1:]):
        s=np.array([v['registration'][j]['shift_px'] for v in patches]); r=np.array([v['registration'][j]['response'] for v in patches]); good=r>=.3
        shifts[p.name]={'n':len(s),'response_median':float(np.median(r)),'response_ge_0_3':int(good.sum()),'all_shift_median_px':np.median(s,axis=0).tolist(),'good_shift_median_px':np.median(s[good],axis=0).tolist() if good.any() else None,'good_abs_shift_p95_px':np.quantile(np.abs(s[good]),.95,axis=0).tolist() if good.any() else None}
    after={p.name:sha(p) for p in FILES}
    if before != after: raise RuntimeError('Входы изменились; результат не записан')
    result={'method':{'grid':'12x8 центров, окна 256x256 исходных пикселей; метрики внутри отступа 8 пикселей','luma':'Y prime = 0.2126 R + 0.7152 G + 0.0722 B, гамма-кодированная шкала 0–255','classes':'По среднему Y базового окна: [0,64), [64,128), [128,192), [192,256); нижняя/верхняя треть градиента внутри интервала, база; одинаковые маски','noise_warning':'Остаток содержит структуру, кодирование и шум; не измерение сенсорного шума','registration':'phaseCorrelate на каждом исходном окне с Hanning, без применения преобразования; низкая response ненадежна','exiftool_version':version,'numpy_version':np.__version__,'opencv_version':cv2.__version__},'sha256_before':before,'sha256_after':after,'metadata_numeric':md,'dqt_payload_sha256':tables,'groups':groups,'registration_summary':shifts,'patches':patches}
    OUT.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
    print('Записано:',OUT)
if __name__=='__main__': main()
