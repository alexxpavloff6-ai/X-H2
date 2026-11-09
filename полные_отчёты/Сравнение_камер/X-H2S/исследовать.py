"""Read-only X-H2S DAT inventory. Requires repository's analysis helpers and cryptography.
FFLZ decoder: tiredboffin/fffw, MIT; see ../../инструменты/Лицензия_fffw.txt.
Offsets are relative to the named container, never inferred runtime addresses.
"""
from pathlib import Path
import sys, importlib.util, hashlib, struct, re, json, csv, zlib, collections
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
PROJECT=ROOT.parent
SOURCE=PROJECT/'Firmware на прочиеFuji'/'FWUP0027.DAT'
sys.path.insert(0,str(ROOT/'инструменты'))
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
base=load('base',ROOT/'анализ_файла.py')
arch=load('arch',ROOT/'Архитектура_2026-11-01'/'проверить_архитектуру.py')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=SOURCE.read_bytes(); data=raw.translate(base.TRANSLATION)
R={'source':str(SOURCE.relative_to(PROJECT)),'size_bytes':len(raw),'sha256':sha(raw),'header_u32_0':struct.unpack_from('<I',raw)[0], 'version_words_hex':[hex(x) for x in struct.unpack_from('<2I',raw,0x204)], 'transformation':'XOR FF','fflz':[],'gzip':[],'signatures':[],'markers':{},'selected_string_counts':{}}
pem=b'''-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOtq7TboeNM3ajHlwuZlmUNvOhOjp2ngfwzHHLp8Q\ni8etG8NUqMYtNehX3AXaPR6bgxFoIV5jgiVDkzmXtYfs/Q==\n-----END PUBLIC KEY-----\n'''
key=serialization.load_pem_public_key(pem)
point=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
R['key']={'source':'https://github.com/tiredboffin/fffw/blob/main/ffun/ports/xh2s/pubkey.pem','git_blob':'0caed9a1491ba45f4ce6a67c6ddde997acfc0380','pem_sha256':sha(pem),'curve':key.curve.name,'point_offsets_xor':[hex(m.start()) for m in re.finditer(re.escape(point),data)]}
for n in range(8,81):
    sig=raw[-n:]
    try:
        r,s=utils.decode_dss_signature(sig)
        key.verify(sig,raw[:-n],ec.ECDSA(hashes.SHA256()))
        R['signatures'].append({'start':hex(len(raw)-n),'length':n,'covered_start':'0x0','covered_length':len(raw)-n,'algorithm':'ECDSA P-256 SHA-256','r':hex(r),'s':hex(s),'verified':True})
    except (ValueError,InvalidSignature): pass
regions=[('DAT_XOR',data)]
for m in re.finditer(re.escape(bytes.fromhex('0040000004000000')),data):
    off=m.start()-12
    if off<0: continue
    u,c,n,pg,align=struct.unpack_from('<5I',data,off)
    if not (20<c<u<256*2**20 and (c+16383)//16384==n and off+c<=len(data)): continue
    try: out=base.unpack_fflz(data,off)
    except (ValueError,IndexError): continue
    info={'dat_offset':hex(off),'packed_size':c,'unpacked_size':u,'pages':n,'page_size':pg,'alignment':align,'sha256_unpacked':sha(out),'first_32':out[:32].hex()}
    R['fflz'].append(info); regions.append(('FFLZ_'+hex(off),out))
(HERE/'строки.tsv').write_text('область\tсмещение_в_области\tкатегории\tстрока\n',encoding='utf-8')
for label,b in regions:
    for pattern in [b'X-H2S',b'ThreadX',b'Linux version ',b'arm,cortex-a53',b'\x7fELF',bytes.fromhex('d00dfeed'),b'ARM\x64']:
        hits=[hex(m.start()) for m in re.finditer(re.escape(pattern),b)]
        if hits: R['markers'][label+':'+pattern.hex()]=hits[:100]
    R['selected_string_counts'][label]={}
    rows=[]
    for m in base.ASCII.finditer(b):
        x=m.group()
        cats=[k for k,p in base.CATEGORIES.items() if p.search(x)]
        if re.search(rb'(?:SHOOT|EXPOS|SHUTTER|APERTURE|ISO_|WB_|WHITE_BALANCE|COLOR|COLOUR|DYNAMIC_RANGE|GRAIN|HIGHLIGHT|SHADOW)',x,re.I): cats.append('съёмка_цвет')
        if cats:
            for c in cats: R['selected_string_counts'][label][c]=R['selected_string_counts'][label].get(c,0)+1
            rows.append([label,hex(m.start()),','.join(cats),x.decode('ascii')])
    with (HERE/'строки.tsv').open('a',encoding='utf-8',newline='') as f:
        csv.writer(f,delimiter='\t',lineterminator='\n').writerows(rows)
# Scan gzip in XORed DAT; only complete streams are counted. Do not extract filesystem paths.
for m in re.finditer(b'\x1f\x8b\x08',data):
    off=m.start()
    try:
        d=zlib.decompressobj(31); out=d.decompress(data[off:],128*1024*1024)
        if not d.eof: continue
        used=len(data)-off-len(d.unused_data)
    except zlib.error: continue
    item={'dat_offset':hex(off),'packed_size':used,'unpacked_size':len(out),'sha256_unpacked':sha(out),'first_32':out[:32].hex()}
    if out.startswith(b'070701'):
        try:
            entries,payloads,parsed=arch.cpio_entries(out)
            item.update({'type':'cpio newc','parsed_bytes':parsed,'entry_count':len(entries),'kinds':dict(collections.Counter(e['kind'] for e in entries))})
            for e in entries:
                e['sha256']=sha(payloads[e['path']])
            with (HERE/'linux_cpio.tsv').open('w',encoding='utf-8',newline='') as f:
                w=csv.DictWriter(f,fieldnames=list(entries[0]),delimiter='\t',lineterminator='\n'); w.writeheader(); w.writerows(entries)
            texts={}
            for name in ['etc/inittab','etc/init.d/ffsys-init.sh','etc/init.d/rpmsg-daemon','etc/rpmsg-daemon.conf']:
                if name in payloads: texts[name]=bytes(payloads[name]).decode('utf-8',errors='replace')
            (HERE/'linux_запуск.json').write_text(json.dumps(texts,ensure_ascii=False,indent=2),encoding='utf-8')
            elf={}
            for name,p in payloads.items():
                if bytes(p[:6])==b'\x7fELF\x02\x01' and ('fujifilm/' in name or name.endswith('rpmsg-daemon')):
                    try: elf[name]=arch.elf_info(bytes(p))
                    except (AssertionError,IndexError,struct.error,UnicodeDecodeError): pass
            item['selected_elf']=elf
            ars={}
            for name,p in payloads.items():
                if name.endswith('libff_api.a'):
                    try: ars[name]=arch.ar_objects(bytes(p))
                    except (AssertionError,IndexError,struct.error,UnicodeDecodeError): pass
            item['selected_ar']=ars
        except (AssertionError,UnicodeDecodeError,ValueError,struct.error): item['type']='cpio candidate, parse failed'
    elif b'Kernel Configuration' in out[:500]:
        item['type']='kernel config'; item['selected_config']=[x for x in out.decode('utf-8',errors='replace').splitlines() if re.match(r'CONFIG_(?:ARM64|SMP|INITRAMFS_SOURCE|NET|CFG80211|BRCMFMAC|RPMSG[^=]*|VIRTIO[^=]*)=',x)]
    R['gzip'].append(item)
# Actual ARM64 sequence at first ARM64 Image header, with file offsets only.
engine=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
code=[]
for m in re.finditer(b'ARM\x64',data):
    off=m.start()-56
    if off<0: continue
    hdr=struct.unpack_from('<2I6Q2I',data,off)
    if hdr[8]!=0x644d5241: continue
    code.append({'header_dat_offset':hex(off),'header_fields':[hex(x) for x in hdr], 'instructions':[{'dat_offset':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in engine.disasm(data[off:off+32],off)]})
R['arm64_images']=code
R['input_sha256_after']=sha(SOURCE.read_bytes()); R['input_unchanged']=R['sha256']==R['input_sha256_after']
(HERE/'сведения.json').write_text(json.dumps(R,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:R[k] for k in ['size_bytes','sha256','version_words_hex','key','signatures','fflz','gzip','arm64_images','input_unchanged']},ensure_ascii=False,indent=2))
