"""Чтение DAT без записи в него; FFLZ по анализ_файла.py (fffw, MIT)."""
from pathlib import Path
import csv, hashlib, importlib.util, json, re, struct, sys, zlib
from collections import Counter
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT.parent / 'Firmware на прочиеFuji' / 'FWUP0030.DAT'
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', ROOT / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
spec = importlib.util.spec_from_file_location('arch', ROOT / 'Архитектура_2026-11-01' / 'проверить_архитектуру.py')
arch = importlib.util.module_from_spec(spec); spec.loader.exec_module(arch)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

def sha(b): return hashlib.sha256(b).hexdigest()
def table(name, fields, rows):
    with (HERE/name).open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter='\t',lineterminator='\n'); w.writeheader(); w.writerows(rows)
raw=SOURCE.read_bytes(); data=raw.translate(base.TRANSLATION)
result={'source':str(SOURCE),'source_bytes':len(raw),'sha256':sha(raw),'decoded_sha256':sha(data),'header_u32':list(struct.unpack_from('<4I',raw)), 'version_words':list(struct.unpack_from('<2I',raw,0x204)), 'transformation':'all bytes XOR FF', 'blocks':[], 'gzip_streams':[], 'signature':{}, 'markers':{}}
key=serialization.load_pem_public_key((HERE/'xt5_pubkey.pem').read_bytes())
for n in range(68,74):
    sig=raw[-n:]
    try:
        r,s=utils.decode_dss_signature(sig)
        key.verify(sig,raw[:-n],ec.ECDSA(hashes.SHA256()))
        result['signature']={'verified':True,'algorithm':'ECDSA P-256 SHA-256','offset':hex(len(raw)-n),'length':n,'covered_offset':0,'covered_length':len(raw)-n,'r_hex':hex(r),'s_hex':hex(s),'key_source':'https://github.com/tiredboffin/fffw/blob/main/ffun/ports/xt5/pubkey.pem','key_git_blob_sha1':'415e72984671fa5dfe7d06745f06e3c2b5ac17fe','key_sha256':sha((HERE/'xt5_pubkey.pem').read_bytes())}
        break
    except (ValueError,InvalidSignature): pass
if not result['signature']: result['signature']={'verified':False,'attempt':'DER lengths 68..73, ECDSA SHA-256 with xt5_pubkey.pem, entire preceding raw bytes'}
point=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
result['signature']['public_point_decoded_file_offset']=hex(data.find(point)) if point in data else None
old=json.loads((ROOT/'сведения.json').read_text(encoding='utf-8'))
oldhash={b['decoded_sha256']:b['file_offset'] for b in old['fflz_blocks']}
regions=[('DAT_XOR',data)]
for m in re.finditer(re.escape(bytes.fromhex('0040000004000000')),data):
    off=m.start()-12
    if off<0: continue
    u,c,n,pg,align=struct.unpack_from('<5I',data,off)
    if not (20<c<u<256*2**20 and (c+16383)//16384==n and off+c<=len(data)): continue
    try: blob=base.unpack_fflz(data,off)
    except (ValueError,IndexError): continue
    h=sha(blob); label='FFLZ_'+hex(off)
    result['blocks'].append({'offset':hex(off),'compressed_bytes_including_header':c,'uncompressed_bytes':u,'pages':n,'page_size':pg,'alignment':align,'sha256':h,'first32':blob[:32].hex(),'identical_xh2_block_offset':oldhash.get(h)})
    regions.append((label,blob))
result['total_uncompressed_fflz_bytes']=sum(b['uncompressed_bytes'] for b in result['blocks'])
patterns={'system':rb'ThreadX|Linux version|arm,cortex-a53|GCC:|COMPILER=|uiSYSQ|uiSYST', 'af':rb'AFCCUS|AFC_CUSTOM|AFSPEED|AF_SPEED|FACEDETECT|FACE_DETECT|EYEAF|EYE_DETECT|DETECT_SUBJ|FOCUS_|AFCHASE|AF_CTRL', 'menu':rb'UI_MENUCOM_ITEM|UI_Q_MENU|UI_MYMENU|UI_FUNC_SET|MENU_CUSTOM|KEY_FACE', 'shooting':rb'SHOOTING|SHUTTER|DRIVE_MODE|EXPOSURE|ISO_SENS|WHITE_BALANCE', 'color':rb'MODE_FSIM_|UI_FILM_SIM_|FILM_SIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC_CHROME|ETERNA|NOSTALG|ACROS'}
compiled={k:re.compile(v,re.I) for k,v in patterns.items()}; records=[]; counts={}
for label,blob in regions:
    counts[label]=Counter()
    for m in re.finditer(rb'[\x20-\x7e]{8,}',blob):
        text=m.group()
        for k,p in compiled.items():
            if p.search(text):
                counts[label][k]+=1; records.append({'region':label,'offset':hex(m.start()),'category':k,'text':text.decode('ascii')})
result['string_counts']={k:dict(v) for k,v in counts.items()}
table('строки_ASCII.tsv',['region','offset','category','text'],records)
# UTF-16 search in both byte alignments; offsets always refer to region start.
menu=[]; pat=re.compile(r'AF-C|AF-S|MY MENU|SHOOTING MENU|FILM SIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC|ETERNA|ACROS|NOSTALG|АВТОФОКУС|ИМИТАЦ|МОДЕЛИРОВ|ПЛ[ЕЁ]НК|БАЛАНС БЕЛОГО|РЕЗКОСТ',re.I)
for label,blob in regions:
    for parity in (0,1):
        s=blob[parity:len(blob)-(len(blob)-parity)%2].decode('utf-16le',errors='replace')
        for m in re.finditer(r'[\x20-\x7e\u0400-\u04ff]{4,}',s):
            if pat.search(m.group()): menu.append({'region':label,'offset':hex(parity+2*m.start()),'text':m.group()})
table('строки_UTF16.tsv',['region','offset','text'],menu); result['utf16_selected_count']=len(menu)
# Search complete gzip streams in uncompressed physical image. False gzip magic ignored.
fsrows=[]
for m in re.finditer(b'\x1f\x8b\x08',data):
    off=m.start()
    try:
        d=zlib.decompressobj(31); content=d.decompress(data[off:],80*1024*1024)
        if not d.eof: continue
        used=len(data)-off-len(d.unused_data)
    except zlib.error: continue
    entry={'offset':hex(off),'compressed_bytes':used,'uncompressed_bytes':len(content),'sha256':sha(content),'prefix_hex':content[:32].hex()}
    if content.startswith(b'070701'):
        try:
            entries,payloads,parsed=arch.cpio_entries(content)
            entry['cpio']={'entries':len(entries),'kinds':dict(Counter(v['kind'] for v in entries)),'parsed_bytes':parsed}
            for item in entries:
                p=payloads[item['path']]; item['sha256']=sha(p) if item['kind']=='обычный файл' else ''; item['gzip_dat_offset']=hex(off); fsrows.append(item)
            interesting={}
            for name,p in payloads.items():
                if name in ('etc/inittab','etc/init.d/ffsys-init.sh','etc/init.d/rpmsg-daemon','etc/rpmsg-daemon.conf'):
                    interesting[name]=bytes(p).decode('utf-8',errors='replace')
                if name.endswith('.a') and bytes(p[:8])==b'!<arch>\n':
                    try: interesting[name]={'objects':arch.ar_objects(bytes(p))}
                    except (AssertionError,ValueError,IndexError,struct.error,UnicodeError): interesting[name]={'parse_error':True}
                if name.startswith(('usr/local/bin/fujifilm/','usr/bin/rpmsg')) and bytes(p[:6])==b'\x7fELF\x02\x01':
                    try: interesting[name]=arch.elf_info(p)
                    except (AssertionError,ValueError,IndexError,struct.error,UnicodeError): pass
            entry['selected_files']=interesting
        except (AssertionError,ValueError,UnicodeError,IndexError): entry['cpio_error']=True
    elif b'Kernel Configuration' in content[:1000]:
        entry['config_selected']=[s for s in content.decode('utf-8',errors='replace').splitlines() if re.match(r'CONFIG_(?:ARM64|SMP|INITRAMFS_SOURCE|NET|CFG80211|BRCMFMAC|RPMSG[^=]*|VIRTIO[^=]*)=',s)]
    result['gzip_streams'].append(entry)
if fsrows: table('каталог_CPIO.tsv',['gzip_dat_offset','path','kind','mode','size','cpio_data_offset','sha256'],fsrows)
for name,needle in {'model':b'X-T5\x00','linux':b'Linux version ','threadx':b'ThreadX Cortex','dtb':bytes.fromhex('d00dfeed'),'arm64_image_magic':b'ARM\x64','elf':b'\x7fELF','ar':b'!<arch>\n','cpio':b'070701'}.items():
    result['markers'][name]=[hex(m.start()) for m in re.finditer(re.escape(needle),data)][:100]
# Disassemble actual entry of uncompressed ARM64 Image header where found.
cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); asm=[]
for pos in result['markers']['arm64_image_magic']:
    off=int(pos,16)-56
    if off<0: continue
    hdr=struct.unpack_from('<2I6Q2I',data,off)
    if hdr[8]!=0x644d5241: continue
    lines=list(cs.disasm_lite(data[off:off+32],off))
    asm.append({'header_offset':hex(off),'text_offset':hex(hdr[2]),'image_size':hdr[3],'flags':hex(hdr[4]),'instructions':[{'offset':hex(a),'bytes':data[a:a+n].hex(),'mnemonic':mn,'operands':op} for a,n,mn,op in lines]})
result['arm64_image_headers']=asm
result['source_hash_after']=sha(SOURCE.read_bytes()); result['source_unchanged']=result['source_hash_after']==result['sha256']
(HERE/'данные.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result[k] for k in ('source_bytes','sha256','version_words','signature','blocks','total_uncompressed_fflz_bytes','string_counts','utf16_selected_count','markers','arm64_image_headers','source_unchanged')},ensure_ascii=False,indent=2))
print('gzip',[(x['offset'],x['uncompressed_bytes'],x.get('cpio')) for x in result['gzip_streams']])
