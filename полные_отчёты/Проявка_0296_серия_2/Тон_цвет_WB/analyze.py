# -*- coding: utf-8 -*-
"""Read-only local comparison; run from repository root. numpy, Pillow, OpenCV required."""
from pathlib import Path
import hashlib, json
import numpy as np
import cv2
from PIL import Image, JpegImagePlugin

BASE = Path('Тестовые фото/Доработка 296 в камере')
OUT = Path(__file__).with_name('results.json')
PATHS = {'0300': BASE / 'DSCF0300.JPG', **{f'{n:04d}': BASE / 'Доработка 2' / f'DSCF{n:04d}.JPG' for n in range(303, 308)}}
BOXES = {'R1':[.34,.04,.70,.25], 'R2':[.43,.40,.56,.62], 'R3':[.18,.64,.40,.78], 'R4':[.02,.08,.13,.37], 'R5':[.74,.42,.86,.52], 'R6':[.79,.66,.95,.78]}

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024*1024): h.update(chunk)
    return h.hexdigest()

def stats(a):
    a=np.asarray(a).ravel()
    if not a.size: return None
    q=np.percentile(a,[5,25,50,75,95])
    return {'n':int(a.size),'mean':float(np.mean(a,dtype=np.float64)),'sd':float(np.std(a,dtype=np.float64)), 'p05':float(q[0]),'p25':float(q[1]),'median':float(q[2]),'p75':float(q[3]),'p95':float(q[4])}

def jpeg_info(p):
    with Image.open(p) as im:
        quant={str(k):v for k,v in im.quantization.items()}
        return {'size':list(im.size),'mode':im.mode,'subsampling_pillow':JpegImagePlugin.get_sampling(im),'quantization_tables':quant,'quantization_sha256':hashlib.sha256(json.dumps(quant,sort_keys=True).encode()).hexdigest(),'file_bytes':p.stat().st_size,'exif_colorspace':im.getexif().get_ifd(34665).get(40961),'icc_present':bool(im.info.get('icc_profile'))}

def lab(rgb):
    return cv2.cvtColor(rgb.astype(np.float32)/255,cv2.COLOR_RGB2LAB)

def convert(l):
    return np.hypot(l[:,:,1],l[:,:,2])

def summarize(l0,l1,c0,c1,mask):
    if not np.any(mask): return {'n':0}
    a=l0[mask]; b=l1[mask]; d=b-a
    ca=c0[mask]; cb=c1[mask]
    result={'n':int(len(a)), 'base':{},'target':{},'difference_target_minus_0300':{}}
    for idx,name in enumerate(('L','a','b')):
        result['base'][name]=stats(a[:,idx]); result['target'][name]=stats(b[:,idx]); result['difference_target_minus_0300'][name]=stats(d[:,idx])
    result['base']['C']=stats(ca); result['target']['C']=stats(cb)
    result['difference_target_minus_0300']['C']=stats(cb-ca)
    result['difference_target_minus_0300']['deltaE76']=stats(np.sqrt(np.sum(d*d,axis=1)))
    return result

def main():
    before={k:sha(p) for k,p in PATHS.items()}
    info={k:jpeg_info(p) for k,p in PATHS.items()}
    if any(x['size'] != info['0300']['size'] for x in info.values()): raise ValueError('Image dimensions differ')
    out={'method':{'difference':'target JPEG minus 0300; ΔE76 is nonnegative Euclidean distance in Lab', 'color':'Pillow decoded 8-bit RGB treated as sRGB; OpenCV float32 RGB2Lab D65/2deg; C=sqrt(a²+b²), hue=atan2(b,a) degrees', 'sampling':'original coordinates x=4k+offset,y=4j+offset, no warp/interpolation; offsets 0 primary and 2 spatial control; neither is independent capture', 'masks':'all masks defined once from 0300 on each grid; L bins [0,20,40,60,80,100.01]; hue 30deg bins with C>=10; boxes x0,y0,x1,y1 normalized, upper bound exclusive', 'registration':'phase correlation grayscale on sampled grid, plus separate 3x3 tiles; translation only, brightness changes can affect estimate; no warp', 'jpeg':'Pillow tables and subsampling identify encoding parameters, not measured compression error; no uncompressed reference', 'boxes':BOXES},'sha256_before':before,'jpeg':info,'grids':{}}
    for off in (0,2):
        with Image.open(PATHS['0300']) as im: base=np.asarray(im.convert('RGB'))[off::4,off::4].copy()
        l0=lab(base); c0=convert(l0); hue=np.mod(np.degrees(np.arctan2(l0[:,:,2],l0[:,:,1])),360)
        gray0=cv2.cvtColor(base,cv2.COLOR_RGB2GRAY).astype(np.float32)
        sh=l0.shape[:2]; masks={'all':np.ones(sh,dtype=bool)}
        for lo in range(0,100,20): masks[f'L_{lo}_{lo+20}']=(l0[:,:,0]>=lo)&(l0[:,:,0]<(100.01 if lo==80 else lo+20))
        for lo in range(0,360,30): masks[f'hue_{lo}_{lo+30}_Cge10']=(c0>=10)&(hue>=lo)&(hue<lo+30)
        h,w=sh
        for name,(x0,y0,x1,y1) in BOXES.items():
            m=np.zeros(sh,dtype=bool); m[int(y0*h):int(y1*h),int(x0*w):int(x1*w)]=True; masks[name]=m
        result={'grid_shape':list(sh),'comparisons':{}}
        for key in list(PATHS)[1:]:
            with Image.open(PATHS[key]) as im: rgb=np.asarray(im.convert('RGB'))[off::4,off::4].copy()
            lt=lab(rgb); ct=convert(lt); gray=cv2.cvtColor(rgb,cv2.COLOR_RGB2GRAY).astype(np.float32)
            shift,response=cv2.phaseCorrelate(gray0,gray)
            tiles=[]
            for iy in range(3):
                for ix in range(3):
                    ys=slice(iy*h//3,(iy+1)*h//3); xs=slice(ix*w//3,(ix+1)*w//3)
                    s,r=cv2.phaseCorrelate(gray0[ys,xs].copy(),gray[ys,xs].copy())
                    tiles.append({'tile':[ix,iy],'shift_sample_pixels':list(map(float,s)),'response':float(r)})
            comp={'phase_global':{'shift_sample_pixels':list(map(float,shift)),'response':float(response)},'phase_3x3':tiles,'masks':{}}
            chosen=masks if off==0 else {'all':masks['all']}
            for name,m in chosen.items(): comp['masks'][name]=summarize(l0,lt,c0,ct,m)
            result['comparisons'][key]=comp
        out['grids'][str(off)]=result
    out['sha256_after']={k:sha(p) for k,p in PATHS.items()}
    out['inputs_unchanged']=before==out['sha256_after']
    if not out['inputs_unchanged']: raise RuntimeError('Source changed during analysis; output not written')
    OUT.write_text(json.dumps(out,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
    print('Saved',OUT,'inputs unchanged:',out['inputs_unchanged'])
if __name__=='__main__': main()
