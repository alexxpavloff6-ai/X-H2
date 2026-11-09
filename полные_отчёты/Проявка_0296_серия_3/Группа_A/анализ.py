#!/usr/bin/env python3
"""Анализ камерных JPEG 0296. Входы только читаются; запись только в этот каталог."""
import argparse, hashlib, json, os, re, subprocess
from pathlib import Path
import numpy as np
from PIL import Image, __version__ as pillow_version

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
P = ROOT / 'Тестовые фото'
OLD = P / 'Доработка 296 в камере'
A = OLD / 'Доработка 3/A'
B = OLD / 'Доработка 3/B/DSCF0318.JPG'
paths = {'RAW0296': P/'DSCF0296.RAF', 'B/0318': B}
paths.update({f'A/{i}': A/f'DSCF{i:04d}.JPG' for i in range(311,319)})
paths.update({f'old/{i}': (OLD if i in (300,301,302) else OLD/'Доработка 2')/f'DSCF{i:04d}.JPG' for i in range(300,311)})
PRIVATE = re.compile(r'(?i)(gps|serial|owner|artist|copyright|creator|author|face|location|position|latitude|longitude|altitude|(?:unique|image|document|original|camera|lens|internal).?id$|file.?number|image.?(number|count)|directory|filename|sourcefile|comment|description|subject|keywords)')
UNKNOWN = re.compile(r'(?i)(?:0x[0-9a-f]+|unknown)')

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''): h.update(b)
    return h.hexdigest()

def safe(d):
    return {k:v for k,v in d.items() if ':' in k and not k.startswith('System:') and not PRIVATE.search(k) and not UNKNOWN.search(k) and not (isinstance(v,str) and v.startswith('(Binary data'))}

def jpeg_headers(data):
    if data[:2] != b'\xff\xd8': raise ValueError('not JPEG')
    pos=2; icc=0; dqt=[]
    while pos<len(data):
        if data[pos]!=255: raise ValueError('bad JPEG')
        while data[pos]==255: pos+=1
        marker=data[pos]; pos+=1
        if marker in (0xda,0xd9): break
        if marker==1 or 0xd0<=marker<=0xd7: continue
        length=int.from_bytes(data[pos:pos+2], 'big')
        if length<2 or pos+length>len(data): raise ValueError('bad segment')
        b=data[pos+2:pos+length]
        if marker==0xe2 and b.startswith(b'ICC_PROFILE\0'): icc+=1
        if marker==0xdb: dqt.append(hashlib.sha256(b).hexdigest())
        pos+=length
    return {'icc_segments_before_sos':icc,'dqt_payload_sha256':dqt}

def measurement(names):
    # RGB — 8-bit кодированные sRGB-значения JPEG. Без приведения профилей и геометрии.
    images=[Image.open(paths[n]).convert('RGB') for n in names]
    if len({im.size for im in images})!=1: raise ValueError('different dimensions')
    w,h=images[0].size
    # Each block contributes its pixel sums; quantiles summarize block means, not uncertainty.
    summaries={k:{'n':0,'sum':0.,'sumabs':0.,'sum2':0.,'block_means':[],'contrasts':[[0.,0.] for _ in range(3)]} for k in ['all','dark','mid','light','flat','textured']}
    totals={'paired_minus_base':0.,'single1_minus_base':0.,'single2_minus_base':0.,'rgb_residual_abs':0.,'pixels':0,'different_rgb_components':0,'max_rgb_diff':0}
    for y in range(0,h,256):
      for x in range(0,w,256):
        box=(x,y,min(x+256,w),min(y+256,h))
        a=[np.asarray(im.crop(box),dtype=np.float32) for im in images]
        # Input order base, joint, single1, single2. Repeat uses base, repeat, base, base.
        lum=[z[:,:,0]*0.2126+z[:,:,1]*0.7152+z[:,:,2]*0.0722 for z in a]
        b,j,s,t=lum; res=j-s-t+b
        rgb=a[1]-a[2]-a[3]+a[0]
        grad=np.zeros_like(b); grad[:,1:]=np.abs(b[:,1:]-b[:,:-1]); grad[1:,:]+=np.abs(b[1:,:]-b[:-1,:])
        masks={'all':np.ones(b.shape,dtype=bool),'dark':b<64,'mid':(b>=64)&(b<192),'light':b>=192,'flat':grad<4,'textured':grad>=12}
        for k,mask in masks.items():
            v=res[mask]; n=v.size
            if n:
                d=summaries[k]; d['n']+=int(n); d['sum']+=float(v.sum(dtype=np.float64)); d['sumabs']+=float(np.abs(v).sum(dtype=np.float64)); d['sum2']+=float(np.square(v,dtype=np.float64).sum()); d['block_means'].append(float(v.mean(dtype=np.float64)))
                for pair,z in zip(d['contrasts'],(j-b,s-b,t-b)):
                    values=z[mask]; pair[0]+=float(values.sum(dtype=np.float64)); pair[1]+=float(np.abs(values).sum(dtype=np.float64))
        n=b.size; totals['pixels']+=n
        for key,val in [('paired_minus_base',j-b),('single1_minus_base',s-b),('single2_minus_base',t-b)]: totals[key]+=float(val.sum(dtype=np.float64))
        totals['rgb_residual_abs']+=float(np.abs(rgb).sum(dtype=np.float64))
        delta=np.abs(a[1]-a[0]); totals['different_rgb_components']+=int(np.count_nonzero(delta)); totals['max_rgb_diff']=max(totals['max_rgb_diff'],int(delta.max()))
    for im in images: im.close()
    n=totals['pixels']; result={'size':[w,h],'mean_y_joint_minus_base':totals['paired_minus_base']/n,'mean_y_single1_minus_base':totals['single1_minus_base']/n,'mean_y_single2_minus_base':totals['single2_minus_base']/n,'mean_abs_rgb_interaction_per_component':totals['rgb_residual_abs']/(n*3),'joint_vs_base_different_component_fraction':totals['different_rgb_components']/(n*3),'joint_vs_base_max_component_difference':totals['max_rgb_diff'],'groups':{}}
    for k,d in summaries.items():
        n=d['n']; means=d['block_means']; result['groups'][k]={'pixels':n,'mean':d['sum']/n if n else None,'mean_absolute':d['sumabs']/n if n else None,'rms':(d['sum2']/n)**.5 if n else None,'contrast_mean_and_mean_abs_joint_single1_single2':[[a/n,c/n] for a,c in d['contrasts']] if n else None,'blocks_with_pixels':len(means),'block_mean_q10_q50_q90':np.quantile(means,[.1,.5,.9]).tolist() if means else None}
    return result

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--exiftool',default=str(Path(os.environ.get('TEMP',os.environ.get('TMP','')))/'xh2metadata/exiftool-13.61/exiftool')); ap.add_argument('--perl',default='C:/Program Files/Git/usr/bin/perl.exe'); args=ap.parse_args()
    cmd=[args.perl,args.exiftool] if args.perl else [args.exiftool]
    version=subprocess.run(cmd+['-ver'],check=True,capture_output=True,text=True).stdout.strip()
    before={k:sha(p) for k,p in paths.items()}; files={}; raw={}
    for k,p in paths.items():
        data=p.read_bytes(); extracted=[]
        for num in (True,False):
            opts=['-j','-G1:4','-a','-u','-U','-charset','UTF8']+(['-n'] if num else [])+['-']
            extracted.append(json.loads(subprocess.run(cmd+opts,input=data,capture_output=True,check=True).stdout)[0])
        raw[k]=extracted[0]
        files[k]={'path':str(p.resolve()).replace('\\','/'),'bytes':len(data),'sha256_before':before[k],'numeric':safe(extracted[0]),'display':safe(extracted[1])}
        if p.suffix.upper()=='.JPG': files[k]['jpeg_headers']=jpeg_headers(data)
    base=safe(raw['old/300']); differences={}; unknown_comparison={}
    for k in files:
        d=safe(raw[k]); differences[k]={key:{'base':base.get(key),'file':d.get(key)} for key in sorted(base.keys()|d.keys()) if base.get(key)!=d.get(key) or (key in base)!=(key in d)}
        a=raw['old/300']; b=raw[k]
        keys={key for key in a.keys()|b.keys() if UNKNOWN.search(key) and not PRIVATE.search(key) and not key.startswith('RAF:FujiFilm_RAFData_')}
        unknown_comparison[k]={'compared_keys':len(keys),'different_or_missing_keys':sum(key not in a or key not in b or a[key]!=b[key] for key in keys)}
    designs={'A0_repeat':['old/300','A/311','old/300','old/300'],'A1_highlight_shadow':['old/300','A/312','old/303','old/304'],'A2_color_chrome':['old/300','A/313','old/301','old/305'],'A3_wb_chrome':['old/300','A/314','old/307','old/305'],'A4_clarity_sharpness':['old/300','A/315','old/308','old/309'],'A5_sharpness_nr':['old/300','A/316','old/309','old/310']}
    measures={}
    for k,names in designs.items():
        print('Измерение',k,flush=True); measures[k]={'files_base_joint_single1_single2':names,'values':measurement(names)}
    after={k:sha(p) for k,p in paths.items()}
    if before!=after: raise RuntimeError('Входы изменились; JSON не записан')
    for k in files: files[k]['sha256_after']=after[k]
    result={'method':{'exiftool':version,'numpy':np.__version__,'pillow':pillow_version,'units':'8-bit кодированные RGB, Y=0.2126R+0.7152G+0.0722B; не линейная яркость','masks':'по базе 0300: темные Y<64, средние 64≤Y<192, светлые Y≥192; текстура сумма абсолютных разностей Y с левым и верхним соседом, flat<4, textured≥12; на границах 256-блоков неполные соседи','blocks':'256×256; q10/50/90 средних по имеющимся пикселям блока — пространственная неоднородность, не ДИ и не независимые кадры','privacy':'только безопасные распознанные теги; неизвестные, приватные и бинарные теги исключены; неизвестные сравниваются только числом различий','provenance':'EXIF и совпадение сцены не доказывают происхождение из RAW'},'files':files,'differences_vs_0300':differences,'unknown_comparison_vs_0300':unknown_comparison,'designs':measures}
    (HERE/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf8')
    print('Записано',HERE/'результат.json',flush=True)
if __name__=='__main__': main()
