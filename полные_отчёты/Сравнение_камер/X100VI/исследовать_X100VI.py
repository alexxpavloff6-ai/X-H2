"""Read-only research of X100VI DAT. FFLZ rules: tiredboffin/fffw (MIT),
see ../../инструменты/Лицензия_fffw.txt. Outputs only inventories, no firmware.
Run from any directory with Python 3 and project dependencies.
"""
from pathlib import Path
from collections import Counter
import csv, hashlib, importlib.util, json, re, struct, sys, zlib

HERE = Path(__file__).resolve().parent
AN = HERE.parent.parent
ROOT = AN.parent
sys.path.insert(0, str(AN/'инструменты'))
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
base=load('base', AN/'анализ_файла.py')
arch=load('arch', AN/'Архитектура_2026-11-01'/'проверить_архитектуру.py')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
H=lambda b: hashlib.sha256(b).hexdigest()
src=ROOT/'Firmware на прочиеFuji'/'FPUPDATE.DAT'
raw=src.read_bytes(); initial=H(raw)
assert initial=='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
data=raw.translate(base.TRANSLATION)
proof={'source':str(src.relative_to(ROOT)), 'bytes':len(raw), 'sha256':initial,
       'transformation':'each byte XOR 0xff (offsets unchanged)',
       'version_words_at_0x204':list(struct.unpack_from('<2I',raw,0x204)),
       'model_offsets':[hex(m.start()) for m in re.finditer(b'X100VI\x00',data)],
       'fflz_scan_pattern':'00 40 00 00 04 00 00 00 at header+12; checks complete decoding and declared length; does not exclude other variants',
       'fflz':[], 'gzip':[], 'signature':{}, 'systems':{}, 'code':[]}
regions={'DAT_XOR_FF':data}
pattern=bytes.fromhex('0040000004000000')
for m in re.finditer(re.escape(pattern),data):
    off=m.start()-12
    if off<0: continue
    u,c,n,p,a=struct.unpack_from('<5I',data,off)
    if not (20<c<u<256*2**20 and (c+16383)//16384==n and off+c<=len(data)): continue
    b=base.unpack_fflz(data,off); regions['FFLZ_'+hex(off)]=b
    proof['fflz'].append({'dat_offset':hex(off),'packed_bytes_including_header':c,'unpacked_bytes':u,'pages':n,'page_size':p,'alignment':a,'packed_sha256':H(data[off:off+c]),'unpacked_sha256':H(b),'first_32_bytes':b[:32].hex()})
    if b.startswith(b'\xff\xd8'):
        pos=2
        while pos+4<=len(b):
            if b[pos]!=0xff: break
            marker=b[pos+1]; size=int.from_bytes(b[pos+2:pos+4],'big')
            if marker in (0xc0,0xc1,0xc2):
                proof['fflz'][-1]['jpeg_frame']={'marker':hex(marker),'precision':b[pos+4], 'height':int.from_bytes(b[pos+5:pos+7],'big'), 'width':int.from_bytes(b[pos+7:pos+9],'big'), 'components':b[pos+9]}
                break
            if size<2: break
            pos+=2+size
# Seek gzip streams in the transformed DAT and in each decompressed block.
for label,buf in list(regions.items()):
    for m in re.finditer(b'\x1f\x8b\x08',buf):
        pos=m.start()
        try:
            dec=zlib.decompressobj(31); unpacked=dec.decompress(buf[pos:],70*1024*1024)
            if not dec.eof or len(unpacked)<1000: continue
        except zlib.error: continue
        used=len(buf)-pos-len(dec.unused_data)
        rec={'region':label,'offset':hex(pos),'packed_bytes':used,'unpacked_bytes':len(unpacked),'sha256':H(unpacked),'prefix':unpacked[:32].hex()}
        proof['gzip'].append(rec)
        if unpacked.startswith(b'070701'):
            entries,payloads,end=arch.cpio_entries(unpacked)
            rec.update({'type':'cpio newc','cpio_bytes_through_trailer':end,'entries':len(entries),'kinds':dict(Counter(e['kind'] for e in entries))})
            with (HERE/'Linux_cpio.tsv').open('w',encoding='utf-8-sig',newline='') as f:
                w=csv.DictWriter(f,fieldnames=['path','kind','mode','size','cpio_data_offset','sha256'],delimiter='\t',lineterminator='\n'); w.writeheader()
                for e in entries: w.writerow({**e,'sha256':H(payloads[e['path']])})
            useful={}
            for name in ['etc/inittab','etc/init.d/ffsys-init.sh','etc/init.d/rpmsg-daemon','etc/rpmsg-daemon.conf']:
                if name in payloads: useful[name]=bytes(payloads[name]).decode('utf-8',errors='replace')
            proof['linux_startup_texts']=useful
            objects={}
            for name in ['usr/lib/libff_api.a','usr/bin/rpmsg-daemon','usr/local/bin/fujifilm/ff_ftp.exe','usr/local/bin/fujifilm/ff_frameio.exe','usr/local/bin/fujifilm/ff_c2pa.exe']:
                if name in payloads:
                    b=bytes(payloads[name])
                    try: objects[name]=arch.ar_objects(b) if b.startswith(b'!<arch>\n') else arch.elf_info(b)
                    except (AssertionError,IndexError,ValueError,struct.error) as e: objects[name]={'parse_error':str(e)}
            proof['linux_selected_executables']=objects
        elif b'Linux/arm64' in unpacked[:200]:
            rec['type']='kernel configuration'
            proof['linux_config_selected']=[x for x in unpacked.decode('utf-8',errors='replace').splitlines() if re.match(r'(?:# )?CONFIG_(?:ARM64|SMP|INITRAMFS_SOURCE|NET|CFG80211|BRCMFMAC|RPMSG[^= ]*|VIRTIO[^= ]*)[= ]',x)]
# Search ASCII identifiers and English/Russian UTF-16LE resources at both parities.
categories={
 'AF':re.compile(rb'AFCCUS|AFC_CUSTOM|AFSPEED|AF_SPEED|FACEDETECT|FACE_DETECT|EYEAF|EYE_DETECT|DETECT_SUBJ|FOCUS_|AFCHASE|AF_CTRL',re.I),
 'menu':re.compile(rb'UI_MENUCOM_ITEM|UI_Q_MENU|UI_MYMENU|UI_FUNC_SET|MENU_CUSTOM',re.I),
 'film':re.compile(rb'MODE_FSIM_|UI_FILM_SIM_|UI_SETP_FILM_SIM|UI_MENUCOM_ITEM_FILM_SIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC_CHROME|ETERNA|NOSTALG|ACROS',re.I),
 'shooting':re.compile(rb'SHOOTING|SHUTTER|DRIVE_MODE|EXPOSURE|WHITE_BALANCE|ISO_SENSITIVITY',re.I),
 'system':re.compile(rb'ThreadX|Linux version|GCC:|[A-Za-z0-9_/.-]+\.(?:c|cpp)\b',re.I)}
with (HERE/'Идентификаторы.tsv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(['region','offset_in_region','category','ascii'])
 counts=Counter()
 for label,buf in regions.items():
  for m in re.finditer(rb'[\x20-\x7e]{6,}',buf):
   for cat,pat in categories.items():
    if pat.search(m.group()):
     w.writerow([label,hex(m.start()),cat,m.group().decode('ascii')]);counts[label+' / '+cat]+=1
 proof['identifier_counts']=dict(counts)
with (HERE/'Тексты_меню_UTF16.tsv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(['region','offset_in_region','text'])
 word=re.compile(r'AF-C|AF-S|MY MENU|SHOOTING MENU|FILM SIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC|ETERNA|ACROS|NOSTALG|АВТОФОКУС|ИМИТАЦ|ПЛ[ЕЁ]НК|БАЛАНС БЕЛОГО|РЕЗКОСТ',re.I)
 counts=Counter()
 for label,buf in regions.items():
  for parity in (0,1):
   text=buf[parity:len(buf)-(len(buf)-parity)%2].decode('utf-16-le',errors='replace')
   for m in re.finditer(r'[\x20-\x7e\u0400-\u04ff]{4,}',text):
    if word.search(m.group()): w.writerow([label,hex(parity+2*m.start()),m.group()]);counts[label]+=1
 proof['utf16_counts']=dict(counts)
proof['systems']['threadx_strings']=[{'offset':hex(m.start()),'value':m.group().decode('ascii')} for m in re.finditer(rb'ThreadX Cortex[^\x00]{0,100}',data)]
proof['systems']['linux_strings']=[{'offset':hex(m.start()),'value':m.group().decode('ascii')} for m in re.finditer(rb'Linux version [^\x00]{0,200}',data)]
proof['systems']['elf_dat']=[{'offset':hex(m.start()),'ident':data[m.start()+4:m.start()+6].hex(),'machine':struct.unpack_from('<H',data,m.start()+18)[0]} for m in re.finditer(b'\x7fELF',data) if m.start()+20<=len(data)]
proof['systems']['dtb_candidates']=[{'offset':hex(m.start()),'big_endian_totalsize':struct.unpack_from('>I',data,m.start()+4)[0]} for m in re.finditer(bytes.fromhex('d00dfeed'),data) if m.start()+8<=len(data)]
proof['systems']['cortex_a53_offsets']=[hex(m.start()) for m in re.finditer(b'arm,cortex-a53',data)]
proof['systems']['arm64_image_magic_offsets']=[hex(m.start()) for m in re.finditer(b'ARM\x64',data)]
# DER-shaped terminal value is not itself proof of authentication.
sig=raw[-72:]
try:
 r,s=utils.decode_dss_signature(sig)
 proof['signature']={'terminal_der_offset':hex(len(raw)-72),'terminal_der_bytes':72,'r_hex':hex(r),'s_hex':hex(s),'tested_sha256_ecdsa_over_prefix':[],'verified':False}
 for p in [HERE/'x100vi_pubkey.pem', *sorted((AN/'инструменты').glob('*.pem'))]:
  key=serialization.load_pem_public_key(p.read_bytes())
  try: key.verify(sig,raw[:-72],ec.ECDSA(hashes.SHA256())); result='valid'; proof['signature']['verified']=True
  except InvalidSignature: result='invalid signature'
  point=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
  proof['signature']['tested_sha256_ecdsa_over_prefix'].append({'key':p.name,'key_sha256':H(p.read_bytes()),'curve':key.curve.name,'public_point_offset_in_inverted_dat':hex(data.find(point)) if data.find(point)>=0 else None,'result':result})
except ValueError: proof['signature']={'terminal_der_parse':'failed'}
# Relative offsets are not runtime addresses.
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM); b=regions['FFLZ_0x1a202bc']; start=16; end=0x90
lines=['; ARM64, смещения относительно распакованного FFLZ 0x1a202bc; не адреса DAT или RAM.', '; Границы функции и назначение не установлены; архитектура отдельно подтверждается ELF.']
for ins in cs.disasm(b[start:end],start):
 lines.append(f'{ins.address:08X}  {ins.bytes.hex(" "):11}  {ins.mnemonic:8} {ins.op_str}')
proof['code'].append({'region':'FFLZ_0x1a202bc','offset_start':hex(start),'offset_end_exclusive':hex(end),'interpretation':'AArch64, semantic function and runtime address unproven'})
(HERE/'Команды_ARM64.asm').write_text('\n'.join(lines)+'\n',encoding='utf-8')
proof['source_sha256_after']=H(src.read_bytes()); assert proof['source_sha256_after']==initial
(HERE/'Доказательства.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'sha256':initial,'blocks':proof['fflz'],'gzip':proof['gzip'],'systems':proof['systems'],'signature':proof['signature'],'counts':proof['identifier_counts'],'utf16':proof['utf16_counts'],'executables':list(proof.get('linux_selected_executables',{}))},ensure_ascii=False,indent=2))
