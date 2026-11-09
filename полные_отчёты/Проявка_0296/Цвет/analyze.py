# -*- coding: utf-8 -*-
"""Local-only, read-only analysis; run from the repository root with Python.
Dependencies: numpy, Pillow, opencv-python, scikit-image. No image is exported.
"""
from pathlib import Path
from io import BytesIO
import hashlib, json, math
import numpy as np
from PIL import Image
import cv2
from skimage.color import rgb2lab

ROOT = Path('.')
DIR = ROOT / 'Тестовые фото' / 'Доработка 296 в камере'
OUT = ROOT / 'Анализ_прошивки' / 'Проявка_0296' / 'Цвет' / 'results.json'
paths = [DIR / f'DSCF030{i}.JPG' for i in range(3)]
raf = ROOT / 'Тестовые фото' / 'DSCF0296.RAF'

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        while chunk := f.read(1024*1024): h.update(chunk)
    return h.hexdigest()

def stats(x):
    x=np.asarray(x).ravel()
    if not x.size: return None
    return {'n':int(x.size),'mean':float(x.mean()),'median':float(np.median(x)),
            'sd':float(x.std()),'p05':float(np.percentile(x,5)),'p95':float(np.percentile(x,95))}

def convert(rgb):
    # OpenCV's float32 sRGB -> CIELAB, D65/2°; input is gamma-encoded sRGB.
    lab=cv2.cvtColor(rgb.astype(np.float32)/255, cv2.COLOR_RGB2LAB)
    c=np.hypot(lab[:,:,1],lab[:,:,2]); h=(np.degrees(np.arctan2(lab[:,:,2],lab[:,:,1]))+360)%360
    return lab,c,h

def process(offset):
    arr=[]; labs=[]; cs=[]; hs=[]
    for p in paths:
        with Image.open(p) as im:
            if im.size != (7728,5152) or im.getexif().get(274,1)!=1: raise ValueError('unexpected size/orientation')
            a=np.array(im.convert('RGB'))[offset::4,offset::4].copy()
        lab,c,h=convert(a); arr.append(a); labs.append(lab); cs.append(c); hs.append(h)
    # User order: 0300 +1, 0301 0, 0302 +2.
    order=[1,0,2]; a=[arr[i] for i in order]; l=[labs[i] for i in order]; c=[cs[i] for i in order]; h=hs[1]
    shape=c[0].shape
    def summaries(mask):
        out={}
        for j,label in enumerate(['0','+1','+2']):
            out[label]={k:stats(v[mask]) for k,v in [('L',l[j][:,:,0]),('a',l[j][:,:,1]),('b',l[j][:,:,2]),('C',c[j])]}
            # Gamma-encoded Rec.709/sRGB luma proxy, not linear luminance.
            yp=(.2126*a[j][:,:,0]+.7152*a[j][:,:,1]+.0722*a[j][:,:,2])/255
            out[label]['Yprime']=stats(yp[mask])
            pix=a[j][mask]
            out[label]['clip_fraction']={'any_0':float(np.any(pix==0,axis=1).mean()),'any_255':float(np.any(pix==255,axis=1).mean()),'all_0':float(np.all(pix==0,axis=1).mean()),'all_255':float(np.all(pix==255,axis=1).mean()),'channels_0':(pix==0).mean(axis=0).tolist(),'channels_255':(pix==255).mean(axis=0).tolist()}
        for x,y,key in [(0,1,'0_to_1'),(1,2,'1_to_2'),(0,2,'0_to_2')]:
            dc=c[y][mask]-c[x][mask]; dl=l[y][:,:,0][mask]-l[x][:,:,0][mask]
            # Mean ratios do not average unstable ratios of individual near-neutral pixels.
            out[key]={'delta_C':stats(dc),'delta_L':stats(dl),'C_ratio_of_means_percent':float(100*(c[y][mask].mean()/c[x][mask].mean()-1)),
                      'fraction_C_increase':float((dc>0).mean()),'fraction_C_unchanged':float((dc==0).mean()),'fraction_C_decrease':float((dc<0).mean())}
        return out
    allmask=np.ones(shape,dtype=bool)
    result={'grid_offset':offset,'grid_stride':4,'grid_shape':list(shape),'global':summaries(allmask)}
    if offset: return result
    result['lightness_bins']={}
    for lo,hi in [(0,20),(20,40),(40,60),(60,80),(80,100.01)]:
        m=(l[0][:,:,0]>=lo)&(l[0][:,:,0]<hi)
        result['lightness_bins'][f'{lo}-{hi}']=summaries(m)
    result['hue_bins_C0_at_least_10']={}
    for lo in range(0,360,30):
        m=(c[0]>=10)&(h>=lo)&(h<lo+30)
        if m.sum()>=20: result['hue_bins_C0_at_least_10'][f'{lo}-{lo+30}']=summaries(m)
    result['chroma_bins']={}
    for lo,hi in [(0,5),(5,10),(10,20),(20,40),(40,200)]:
        m=(c[0]>=lo)&(c[0]<hi)
        if m.sum(): result['chroma_bins'][f'{lo}-{hi}']=summaries(m)
    # Fixed normalized rectangles, selected before measurement; coordinates are x0,y0,x1,y1.
    boxes={'R1':[.34,.04,.70,.25],'R2':[.43,.40,.56,.62],'R3':[.18,.64,.40,.78], 'R4':[.02,.08,.13,.37], 'R5':[.74,.42,.86,.52], 'R6':[.79,.66,.95,.78]}
    result['regions']={}
    for name,(x0,y0,x1,y1) in boxes.items():
        mask=np.zeros(shape,dtype=bool); mask[int(y0*shape[0]):int(y1*shape[0]),int(x0*shape[1]):int(x1*shape[1])]=True
        result['regions'][name]={'normalized_box':[x0,y0,x1,y1],'statistics':summaries(mask)}
    # Spatial block bootstrap on 12x8 equal-ish rectangular tiles; resample tiles, not pixels.
    tilemeans=[]
    for yy in np.array_split(np.arange(shape[0]),8):
        for xx in np.array_split(np.arange(shape[1]),12):
            s=np.ix_(yy,xx); tilemeans.append([float(z[s].mean()) for z in c]+[float(z[:,:,0][s].mean()) for z in l])
    tilemeans=np.array(tilemeans); rng=np.random.default_rng(296); picks=rng.integers(0,len(tilemeans),(3000,len(tilemeans)))
    boot=tilemeans[picks].mean(axis=1)
    result['spatial_tile_bootstrap']={'description':'96 spatial tiles, 3000 tile resamples, seed 296; conditional on this single image, not camera repeatability','C_0_to_1_ratio_percent_95':np.percentile(100*(boot[:,1]/boot[:,0]-1),[2.5,97.5]).tolist(),'C_1_to_2_ratio_percent_95':np.percentile(100*(boot[:,2]/boot[:,1]-1),[2.5,97.5]).tolist(),'L_0_to_1_mean_difference_95':np.percentile(boot[:,4]-boot[:,3],[2.5,97.5]).tolist(),'L_1_to_2_mean_difference_95':np.percentile(boot[:,5]-boot[:,4],[2.5,97.5]).tolist()}
    # Independent CIELAB implementation on a fixed sparse subgrid: quantization differences expected.
    sample=a[0][::32,::32]; ref=rgb2lab(sample.astype(np.float64)/255); cv=convert(sample)[0]
    result['lab_crosscheck']={'sample_n':int(sample.shape[0]*sample.shape[1]),'opencv_minus_skimage_mean_abs_Lab':np.mean(np.abs(cv-ref),axis=(0,1)).tolist(),'opencv_minus_skimage_max_abs_Lab':np.max(np.abs(cv-ref),axis=(0,1)).tolist()}
    # Same-position equality is a geometric control, not a registration optimization.
    gray=[cv2.cvtColor(v,cv2.COLOR_RGB2GRAY).astype(np.float32) for v in a]
    shift,response=cv2.phaseCorrelate(gray[0],gray[2])
    result['geometry_control']={'phase_correlation_0_vs_2_shift_sample_pixels':[float(z) for z in shift],'response':float(response),'one_sample_pixel_original_pixels':4,'interpretation':'diagnostic global translation only; no warp applied'}
    return result

def preview():
    data=raf.read_bytes()
    if not data.startswith(b'FUJIFILMCCD-RAW '): raise ValueError('unexpected RAF signature')
    off=int.from_bytes(data[84:88], 'big'); length=int.from_bytes(data[88:92], 'big')
    if off<148 or length<=0 or off+length>len(data): raise ValueError('invalid RAF preview bounds')
    im=Image.open(BytesIO(data[off:off+length])); im.load()
    rgb=np.array(im.convert('RGB'))[::4,::4]; lab,c,_=convert(rgb)
    return {'extraction':'RAF header big-endian JPEG offset and length at 84 and 88; no file written','offset_bytes':off,'length_bytes':length,'size':list(im.size),'sample_stride':4,'L':stats(lab[:,:,0]),'a':stats(lab[:,:,1]),'b':stats(lab[:,:,2]),'C':stats(c),'note':'Unaligned independent embedded preview; crop, resolution and rendering may differ; not a Color setting control.'}

inputs=paths+[raf]; before={str(p):sha(p) for p in inputs}
res={'method':{'mapping':'0300 +1, 0301 0, 0302 +2 per user, not independently inferred','sampling':'same original pixel coordinates, every fourth pixel each axis; no registration, interpolation or crop','color':'sRGB (EXIF ColorSpace=1, no ICC), OpenCV float RGB-to-Lab D65/2°, C=sqrt(a²+b²), hue=atan2(b,a); numerical CIELAB summaries, not ISP coefficients','percent':'100*(mean C target / mean C source - 1); not mean of pixel ratios','bins':'based on Color 0; hue in degrees from +a toward +b; hue excludes C<10','limitations':'one RAF and one camera rendering per level; JPEG quantization, other hidden settings, and scene dependence cannot be separated'},'sha256_before':before,'primary':process(0),'independent_grid_control':process(2),'raf_embedded_preview':preview()}
res['sha256_after']={str(p):sha(p) for p in inputs}; res['inputs_unchanged']=res['sha256_before']==res['sha256_after']
OUT.write_text(json.dumps(res,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
print('Wrote',OUT,'inputs unchanged:',res['inputs_unchanged'])
