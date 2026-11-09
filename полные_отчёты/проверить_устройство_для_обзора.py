"""Проверяет признаки архитектуры, разделов и языков без изменения DAT."""
from pathlib import Path
import hashlib,json,struct,re
ROOT=Path(__file__).resolve().parent
src=ROOT.parent/'FIRMWARE'/'ver 5.30'/'FWUP0028.DAT'
raw=src.read_bytes();sha=hashlib.sha256(raw).hexdigest()
expected=json.loads((ROOT/'сведения.json').read_text(encoding='utf-8'))
assert sha==expected['sha256']
d=raw.translate(bytes.maketrans(bytes(range(256)),bytes(255-i for i in range(256))))
off=0x3c40274
head=struct.unpack_from('>10I',d,off)
assert head[0]==0xd00dfeed
dt=d[off:off+head[1]];st=dt[head[3]:head[3]+head[8]]
pos=head[2];stack=[];nodes=[]
def cstr(b,i):return b[i:b.index(b'\0',i)].decode('ascii',errors='replace')
while pos<len(dt):
 token=struct.unpack_from('>I',dt,pos)[0];pos+=4
 if token==1:
  name=cstr(dt,pos);pos=(pos+len(name)+1+3)&~3;stack.append(name)
 elif token==2:stack.pop()
 elif token==3:
  n,no=struct.unpack_from('>II',dt,pos);pos+=8
  v=dt[pos:pos+n];pos=(pos+n+3)&~3
  key=cstr(st,no);path='/'+'/'.join(s for s in stack if s)
  ascii_ok=bool(v) and all(32<=b<127 or b==0 for b in v)
  nodes.append({'node':path,'property':key,'bytes':v.hex(' ').upper(),
                'text':v.rstrip(b'\0').decode('ascii').replace('\0',' | ') if ascii_ok else None,
                'u32_be':list(struct.unpack('>'+str(n//4)+'I',v)) if n and n%4==0 else None})
 elif token==4:pass
 elif token==9:break
 else:raise ValueError(token)
selected=[z for z in nodes if z['property'] in ['compatible','model','device_type'] and (z['node']=='/' or '/cpus' in z['node'])]
strings={}
for label,pattern in [('Cortex-A53',rb'arm,cortex-a53'),('CEVA-XM6',rb'CEVA-XM6'),('C_source',rb'(?:src/egl/client/dmpdevconf\.c|/drivers/csl/src/mss\.c)'),('Linux',rb'Linux version [^\0]{1,170}'),('ThreadX',rb'ThreadX [^\0]{1,120}')]:
 hits=list(re.finditer(pattern,d))
 strings[label]={'count_in_inverted_DAT':len(hits),
                 'first_hits':[{'file_offset':hex(m.start()),'text':m.group().decode('ascii',errors='replace')} for m in hits[:5]]}
elfoff=0x4137274
elf={'ident':d[elfoff:elfoff+16].hex(' ').upper(),'class':d[elfoff+4],
     'data_encoding':d[elfoff+5],'type':struct.unpack_from('<H',d,elfoff+16)[0],
     'machine':struct.unpack_from('<H',d,elfoff+18)[0]}
result={'source':str(src),'source_size':len(raw),'source_sha256':sha,
        'device_tree_header':list(head),'root_and_cpu_properties':selected,
        'all_device_tree_properties':nodes,'string_evidence':strings,'elf':elf,
        'source_unchanged':hashlib.sha256(src.read_bytes()).hexdigest()==sha}
(ROOT/'Обзор_прошивки_доказательства.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='all_device_tree_properties'},ensure_ascii=True,indent=2))
