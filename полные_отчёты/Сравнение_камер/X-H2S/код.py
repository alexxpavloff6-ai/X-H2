"""Inspect actual ARM64 instructions, without executing camera code."""
from pathlib import Path
import sys,importlib.util,struct,zlib,json,hashlib
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]; PROJECT=ROOT.parent
sys.path.insert(0,str(ROOT/'инструменты'))
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=load('base',ROOT/'анализ_файла.py'); arch=load('arch',ROOT/'Архитектура_2026-11-01'/'проверить_архитектуру.py')
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
raw=(PROJECT/'Firmware на прочиеFuji'/'FWUP0027.DAT').read_bytes(); d=raw.translate(base.TRANSLATION)
assert hashlib.sha256(raw).hexdigest()=='87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b'
fs,_=arch.gzip_at(d,0x42dfdcc); entries,payloads,_=arch.cpio_entries(fs); ar=bytes(payloads['usr/lib/libff_api.a'])
pos=8; names=b''; objects={}
while pos+60<=len(ar):
 h=ar[pos:pos+60];assert h[58:60]==b'`\n';name=h[:16].decode().strip(); size=int(h[48:58]);b=ar[pos+60:pos+60+size]
 if name=='//':names=b
 elif name not in ('/','/SYM64/'):
  if name.startswith('/') and name[1:].isdigit():name=names[int(name[1:]):].split(b'/\n',1)[0].decode()
  objects[name.rstrip('/')]=b
 pos+=60+size+size%2
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); results=[]
for obj,wanted in [('os_unix.o','os_zalloc'),('ff_wlan_api.o','ch_to_freq'),('common.o','hex2byte')]:
 b=objects[obj]; hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',b); sections=[struct.unpack_from('<IIQQQQIIQQ',b,hdr[6]+j*hdr[11]) for j in range(hdr[12])]
 for sec in sections:
  if sec[1]!=2:continue
  strings=sections[sec[6]];strtab=b[strings[4]:strings[4]+strings[5]]
  for p in range(sec[4],sec[4]+sec[5],sec[9]):
   name,info,other,idx,value,size=struct.unpack_from('<IBBHQQ',b,p);label=strtab[name:].split(b'\0',1)[0].decode(errors='replace')
   if label!=wanted or idx>=len(sections):continue
   text=sections[idx];start=text[4]+value;code=b[start:start+size]
   results.append({'archive':'gzip cpio usr/lib/libff_api.a','object':obj,'symbol':label,'section_index':idx,'section_relative_offset':hex(value),'object_file_offset':hex(start),'symbol_size':size,'object_sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'section_offset':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(code,value)],'note':'ET_REL: branch targets needing relocation are unresolved, offsets are not runtime addresses.'})
block=base.unpack_fflz(d,0xf20274)
results.append({'container':'FFLZ DAT 0xf20274','offset_in_unpacked':'0x10','note':'No identified symbol or semantic attribution; disassembly is a candidate code fragment.','instructions':[{'block_offset':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(block[0x10:0x50],0x10)]})
(HERE/'код.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(results,ensure_ascii=False,indent=2))
