"""Две модели ARM64: сохранитель -> читатель и отдельно caller -> setter.
DAT только читаются; адреса и синтетические условия описаны в отчёте.
Запуск из любого каталога: python путь/исследовать.py
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AN = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(AN / 'инструменты'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
spec = importlib.util.spec_from_file_location('unpack', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
REG = [getattr(R, 'UC_ARM64_REG_X%d' % i) for i in range(31)]
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MODELS = {
 'X-H2S': dict(file='FWUP0027.DAT', sha='87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b', offsets=[0x300274,0x840274], starts=[0x1421000,0x2cca000],
   state=0x299c40c, compare=0x164b194, stop=0x164b62c, ui=0x236e100, old=0x236bc70, error=0x236b408, reader=0x2f1328c, writer=0x2f1111c, caller=0x32d2520, setter=0x18827c8, after=0x32d253c, array=0x4c935c8),
 'X-T5': dict(file='FWUP0030.DAT', sha='790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e', offsets=[0x300274,0x820274], starts=[0x1101000,0x28eb000],
   state=0x25bcccc, compare=0x132a978, stop=0x132ae4c, ui=0x2003300, old=0x2001080, error=0x20007ec, reader=0x2b3b53c, writer=0x2b38e3c, caller=0x2ef90a0, setter=0x1559350, after=0x2ef90b8, array=0x4ba6948),
}
def put(u, a, v): u.mem_write(a, struct.pack('<I',v & 0xffffffff))
def get(u, a): return struct.unpack('<I', u.mem_read(a,4))[0]
def reset(u, args):
 for r in REG: u.reg_write(r,0)
 u.mem_write(0x7000d000,bytes(0x3000)); u.reg_write(R.UC_ARM64_REG_SP,0x7000f000); u.reg_write(R.UC_ARM64_REG_X30,0x70000000)
 for n,v in args.items(): u.reg_write(REG[n],v)
def run(u,start,stops):
 seen=[]
 def hook(uc,addr,size,user):
  if addr in stops:
   seen.append(addr); uc.emu_stop()
 h=u.hook_add(UC_HOOK_CODE,hook)
 try: u.emu_start(start,0x70000000,count=200000,timeout=3000000)
 finally: u.hook_del(h)
 if not seen: raise RuntimeError('граница не достигнута: %x pc=%x' % (start,u.reg_read(R.UC_ARM64_REG_PC)))
 return seen[0]
def main():
 result={}
 for name,c in MODELS.items():
  raw=(ROOT/'Firmware на прочиеFuji'/c['file']).read_bytes(); sha=hashlib.sha256(raw).hexdigest(); assert sha==c['sha']
  data=raw.translate(base.TRANSLATION)
  blocks=[(0x40000,data[0x60274:0x7e5b4])]
  for off,expect in zip(c['offsets'],c['starts']):
   b=base.unpack_fflz(data,off); address=struct.unpack_from('<Q',b,8)[0]; assert address==expect,(name,hex(address)); blocks.append((address,b))
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
  for a,b in blocks: u.mem_write(a,b)
  u.mem_map(0x60000000,0x40000);u.mem_map(0x70000000,0x10000)
  cases=[]
  for ui in (14,0):
   put(u,c['ui'],ui);put(u,c['old'],0xffffffff);put(u,c['state'],0xffffffff);put(u,c['error'],0)
   reset(u,{})
   stop=run(u,c['compare'],{c['stop']}); state=get(u,c['state']); error=get(u,c['error'])
   assert state==({14:13,0:0}[ui]) and error==0
   reset(u,{0:0x60000000})
   dest=run(u,c['reader'],{c['writer']})
   value=u.reg_read(REG[1]) & 0xffffffff
   cases.append(dict(ui=ui,state=state,error=error,reader_stop=hex(dest),writer_x0=hex(u.reg_read(REG[0])),writer_w1=value))
  setter_cases=[]
  for supplied in (13,0):
   for handle in (0xffff0000,0xffffffff):
    reset(u,{19:handle,20:0,0:0})
    if name=='X-H2S': put(u,c['array'],supplied)
    else: put(u,0x7000f068,supplied)
    dest=run(u,c['caller'],{c['setter'],c['after']})
    setter_cases.append(dict(synthetic_value=supplied,handle=hex(handle),boundary=hex(dest),setter_frame=hex(u.reg_read(REG[0])) if dest==c['setter'] else None,setter_value=(u.reg_read(REG[1]) & 0xffffffff) if dest==c['setter'] else None))
    assert (dest==c['setter']) == (handle==0xffff0000)
    if dest==c['setter']: assert u.reg_read(REG[1]) & 0xffffffff == supplied
  ranges = [(c['reader'],c['reader']+0x6c),(c['caller'],c['caller']+(0x1c if name=='X-H2S' else 0x18))]
  snippets=[]
  for start,end in ranges:
   for ins in cs.disasm(bytes(u.mem_read(start,end-start)),start): snippets.append(dict(address=hex(ins.address),bytes=ins.bytes.hex(),instruction=ins.mnemonic+' '+ins.op_str))
  result[name]=dict(sha256=sha,blocks=[dict(address=hex(a),size=len(b),sha256=hashlib.sha256(b).hexdigest()) for a,b in blocks],saved_reader=cases,caller_to_setter=setter_cases,instructions=snippets)
 out=HERE/'результаты.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:{'saved_reader':v['saved_reader'],'caller_to_setter':v['caller_to_setter']} for k,v in result.items()},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
