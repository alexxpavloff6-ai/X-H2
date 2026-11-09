"""Побайтовое сравнение конкретных модулей и архивов двух предоставленных DAT."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys, zlib
from collections import Counter
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'инструменты'))
spec=importlib.util.spec_from_file_location('arch',ROOT/'Архитектура_2026-11-01'/'проверить_архитектуру.py'); arch=importlib.util.module_from_spec(spec); spec.loader.exec_module(arch)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
sha=lambda b:hashlib.sha256(b).hexdigest()
xt=(ROOT.parent/'Firmware на прочиеFuji'/'FWUP0030.DAT').read_bytes().translate(bytes.maketrans(bytes(range(256)),bytes(255-i for i in range(256))))
xh=(ROOT.parent/'FIRMWARE'/'ver 5.30'/'FWUP0028.DAT').read_bytes().translate(bytes.maketrans(bytes(range(256)),bytes(255-i for i in range(256))))
info={'comparisons':{},'threadx_strings':{},'queue':{},'linux':{},'device_tree':{}}
for off,size,name in [(0x60274,0x1e340,'low_module'),(0x3cb0274,64,'linux_image_header'),(0x413b474,14209,'config_gzip'),(0x42dfdcc,20303473,'filesystem_gzip')]:
    a,b=xt[off:off+size],xh[off:off+size]; info['comparisons'][name]={'dat_offset':hex(off),'size':size,'xt5_sha256':sha(a),'xh2_sha256_same_range':sha(b),'equal':a==b}
for name,im in [('xt5',xt),('xh2',xh)]:
    mod=im[0x60274:0x60274+0x1e340]
    info['threadx_strings'][name]=[{'offset':hex(0x60274+m.start()),'text':m.group().decode()} for m in re.finditer(rb'[\x20-\x7e]{5,}',mod) if any(s in m.group() for s in (b'ThreadX',b'uiSYSQ',b'uiSYST'))]
    for needle in (b'Linux version ',b'arm,cortex-a53'):
        offsets=[m.start() for m in re.finditer(re.escape(needle),im)]
        info['linux'].setdefault(name,{})[needle.decode()]=[{'offset':hex(o),'text':im[o:im.find(b'\0',o)].decode('ascii',errors='replace')} for o in offsets[:20]]
    dt=im.find(bytes.fromhex('d00dfeed'))
    if dt>=0:
        length=struct.unpack_from('>I',im,dt+4)[0]
        info['device_tree'][name]={'offset':hex(dt),'declared_size':length,'sha256':sha(im[dt:dt+length])}
cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
# This is a file-derived ARM64 module mapped as the reference module, not claimed runtime mapping.
for start,end in [(0x55f80,0x55fac),(0x55fbc,0x55fec)]:
    foff=0x60274+(start-0x40000); buf=xt[foff:foff+end-start]
    info['queue'][hex(start)]={'file_offset':hex(foff),'bytes':buf.hex(),'instructions':[{'virtual':hex(a),'dat':hex(foff+a-start),'bytes':buf[a-start:a-start+n].hex(),'instruction':m+' '+o} for a,n,m,o in cs.disasm_lite(buf,start)]}
    info['queue'][hex(start)]['identical_xh2_same_file_range']=buf==xh[foff:foff+len(buf)]
# Complete Linux cpio normal-file comparisons by path and SHA-256.
fs={}
for name,im in [('xt5',xt),('xh2',xh)]:
    buf,used=arch.gzip_at(im,0x42dfdcc); ent,payload,parsed=arch.cpio_entries(buf)
    fs[name]=(ent,payload); info['linux'][name]['cpio_sha256']=sha(buf); info['linux'][name]['cpio_gzip_length']=used
by={name:{e['path']:e for e in ent} for name,(ent,p) in fs.items()}
shared=set(by['xt5']) & set(by['xh2']); a,b=fs['xt5'][1],fs['xh2'][1]
same=[p for p in shared if by['xt5'][p]['kind']==by['xh2'][p]['kind']=='обычный файл' and sha(a[p])==sha(b[p])]
info['comparisons']['cpio']={'shared_paths':len(shared),'xt5_only':sorted(set(by['xt5'])-shared),'xh2_only':sorted(set(by['xh2'])-shared),'identical_regular_file_contents':len(same),'shared_regular_files':sum(by['xt5'][p]['kind']==by['xh2'][p]['kind']=='обычный файл' for p in shared),'interesting_hashes':{p:{'xt5':sha(a[p]),'xh2':sha(b[p]),'identical':sha(a[p])==sha(b[p])} for p in ['usr/lib/libff_api.a','usr/bin/rpmsg-daemon','etc/inittab','etc/init.d/ffsys-init.sh','usr/local/bin/fujifilm/ff_ftp.exe','usr/local/bin/fujifilm/ff_frameio.exe','usr/local/bin/fujifilm/ff_c2pa.exe'] if p in shared}}
(HERE/'сравнение_и_код.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in info.items() if k!='comparisons'},ensure_ascii=False,indent=2)); print(json.dumps(info['comparisons'],ensure_ascii=False,indent=2))
