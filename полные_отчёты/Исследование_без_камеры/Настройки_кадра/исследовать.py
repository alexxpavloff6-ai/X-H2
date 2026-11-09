"""Непрерывная локальная проверка входного буфера и setter; DAT только читаются."""
from pathlib import Path
import sys, importlib.util, hashlib, struct, json
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
AN=HERE.parents[1]; ROOT=AN.parent
sys.path.insert(0,str(AN/'инструменты'))
spec=importlib.util.spec_from_file_location('base',AN/'анализ_файла.py'); base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn import arm64_const as R
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MODELS=[
 dict(name='X-T5 4.31',path='Firmware на прочиеFuji/FWUP0030.DAT',sha='790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',offsets=[0x300274,0x820274],entry=0x2d0820c,copy_call=0x2d08284,copy_return=0x2d08288,dispatch=0x2d082f0,processor=0x14ed9b0,check=0x14edccc,end=0x14edce8,gate_stop=0x2d082f8,setter=0x1558558,global_buf=0x38a8718,global_gate=0x38a8700,field=0x108,saved_mode=0x25bcccc,size=0x920),
 dict(name='X100VI 1.31',path='Firmware на прочиеFuji/FPUPDATE.DAT',sha='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',offsets=[0x9c02bc,0x10e02bc],entry=0x2fd1734,copy_call=0x2fd17ac,copy_return=0x2fd17b0,dispatch=0x2fd1818,processor=0x15c11ec,check=0x15c1524,end=0x15c1540,gate_stop=0x2fd1820,setter=0x1629628,global_buf=0x41d1128,global_gate=0x41d1110,field=0x114,saved_mode=0x27f7a54,size=0x958)
]

SEARCH_MODELS=[
 ('X-H2 5.30','FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274]),
 ('X-H2S 7.30','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274]),
]
SEARCH_MODELS.extend((m['name'],m['path'],m['sha'],m['offsets']) for m in MODELS)
SIGNATURE=bytes.fromhex('1f0000f1241840fac0070054ff0302d1fd7b03a9fdc30091f35304a9f55b05a9f76306a9f93b00f9f30300aaf40302aaf50303aa981c0012f903052af703062af603072a')

def search_exact():
 out=[]
 for name,path,expected,offsets in SEARCH_MODELS:
  p=ROOT/path; before=sha(p)
  if before!=expected:raise ValueError('unexpected input hash '+name)
  data=p.read_bytes().translate(base.TRANSLATION);matches=[];ranges=[]
  for offset in offsets:
   block=base.unpack_fflz(data,offset);addr=struct.unpack_from('<Q',block,8)[0]
   ranges.append({'dat_offset':hex(offset),'base':hex(addr),'size':len(block),'sha256':hashlib.sha256(block).hexdigest()})
   start=0
   while True:
    pos=block.find(SIGNATURE,start)
    if pos<0:break
    matches.append({'address':hex(addr+pos),'block_offset':hex(pos),'aligned':(addr+pos)%4==0})
    start=pos+1
  after=sha(p)
  if before!=after:raise RuntimeError('DAT changed during exact search')
  out.append({'name':name,'path':path,'sha256_before':before,'sha256_after':after,'blocks':ranges,'matches':matches})
 return out

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest()

def words(u,a):return struct.unpack('<I',bytes(u.mem_read(a,4)))[0]
def put(u,a,v):u.mem_write(a,struct.pack('<I',v))

def run(m,blocks,case):
 label,source,old,gate,nullsrc,nullthird=case
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
 for a,b in blocks:u.mem_write(a,b)
 u.mem_map(0x70000000,0x20000);src=0x70001000;obj=0x70003000;ret=0x7001f000;sp=0x7001e000
 put(u,src+0x144,source);put(u,obj+m['field'],old);put(u,m['global_gate'],gate)
 # Ненулевые сторожа вне слова показывают, что большой буфер действительно скопирован.
 u.mem_write(src+0x140,b'ABCD');u.mem_write(src+0x148,b'WXYZ')
 for r,v in [(R.UC_ARM64_REG_X0,obj),(R.UC_ARM64_REG_X1,0 if nullsrc else src),(R.UC_ARM64_REG_X2,0 if nullthird else 0x70004000),(R.UC_ARM64_REG_X3,0x70005000),(R.UC_ARM64_REG_X30,ret),(R.UC_ARM64_REG_SP,sp)]:u.reg_write(r,v)
 points={m[k]:k for k in ('entry','copy_call','copy_return','dispatch','processor','check','setter','end','gate_stop')};points[ret]='research_return'
 trace=[];mode_reads=[]
 def code(uc,addr,size,user):
  if addr in points:
   trace.append({'pc':hex(addr),'point':points[addr],'x0':hex(uc.reg_read(R.UC_ARM64_REG_X0)),'x1':hex(uc.reg_read(R.UC_ARM64_REG_X1)),'x2':hex(uc.reg_read(R.UC_ARM64_REG_X2)),'x19':hex(uc.reg_read(R.UC_ARM64_REG_X19)),'x20':hex(uc.reg_read(R.UC_ARM64_REG_X20))})
   if addr in (m['end'],m['gate_stop'],ret):uc.emu_stop()
 def read(uc,access,addr,size,value,user):
  if addr<m['saved_mode']+4 and addr+size>m['saved_mode']:mode_reads.append({'address':hex(addr),'size':size})
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,read)
 u.emu_start(m['entry'],0,count=1000000)
 pc=u.reg_read(R.UC_ARM64_REG_PC);visited={x['point'] for x in trace};final=words(u,obj+m['field']);copied=bytes(u.mem_read(m['global_buf'],m['size']))==bytes(u.mem_read(src,m['size']))
 result={'case':label,'synthetic_source_word':source,'synthetic_old_field':old,'synthetic_gate':gate,'null_source':nullsrc,'null_third_argument':nullthird,'end_pc':hex(pc),'trace':trace,'source_copy_complete':copied,'global_word':words(u,m['global_buf']+0x144),'field_after':final,'setter_visited':'setter' in visited,'saved_mode_reads':mode_reads}
 if label in ('change','equal','out_of_range','special'):
  expected=source if source<=22 or source==255 else 0
  if pc!=m['end'] or final!=expected or not copied or result['setter_visited']!=(old!=expected):raise AssertionError(result)
 elif label=='gate_one':
  if pc!=m['gate_stop'] or not copied or final!=old or result['setter_visited']:raise AssertionError(result)
 elif label in ('null_source','null_third'):
  if pc!=ret or final!=old or 'copy_call' in visited or result['setter_visited']:raise AssertionError(result)
 if mode_reads:raise AssertionError('Unexpected read of known MODE cell')
 return result

def main():
 out={'method':'Original ARM64 instructions entered at upstream function, continuous VM execution through original copy and conditional field setter to before next instruction; no function hooks, patches, or artificial register resets mid-run. RAM/stack and inputs synthetic; global gate manually initialized. Direct input source not proven to originate from saved MODE or UI. Null-pointer return and gate branch are VM controls. A separate later getter/processing path from previous research is not part of this run.', 'exact_search':{'signature_hex':SIGNATURE.hex(),'scope':'Two decompressed blocks per model; exact byte pattern only, unaligned matches reported. Does not exclude reordered, indirect or semantically equivalent code.','models':search_exact()},'models':[]}
 cases=[('change',13,7,0,False,False),('equal',13,13,0,False,False),('out_of_range',23,13,0,False,False),('special',255,13,0,False,False),('gate_one',13,7,1,False,False),('null_source',13,7,0,True,False),('null_third',13,7,0,False,True)]
 for m in MODELS:
  p=ROOT/m['path'];before=sha(p)
  if before!=m['sha']:raise ValueError('unexpected input hash '+m['name'])
  data=p.read_bytes().translate(base.TRANSLATION);blocks=[]
  for offset in m['offsets']:
   b=base.unpack_fflz(data,offset);a=struct.unpack_from('<Q',b,8)[0];blocks.append((a,b))
  # Виртуальная загрузка — ровно в порядке блоков DAT; вторая область перекрывает первую.
  experiments=[run(m,blocks,c) for c in cases]
  cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);windows={}
  for key in ('entry','copy_call','dispatch','processor','check','setter'):
   addr=m[key]
   for a,b in reversed(blocks):
    if a<=addr and addr+16<=a+len(b):
     windows[key]=[{'pc':hex(ins.address),'bytes':bytes(ins.bytes).hex(),'mnemonic':ins.mnemonic,'op_str':ins.op_str} for ins in cs.disasm(b[addr-a:addr-a+16],addr)];break
   if key not in windows:raise ValueError('address not in image '+key)
  after=sha(p)
  if before!=after:raise RuntimeError('DAT changed while analyzing')
  out['models'].append({'name':m['name'],'path':m['path'],'sha256_before':before,'sha256_after':after,'entry':hex(m['entry']),'global_copy':hex(m['global_buf']),'copy_size':hex(m['size']),'field_offset':hex(m['field']),'saved_mode_address':hex(m['saved_mode']),'instruction_windows':windows,'experiments':experiments})
  print(m['name'],[(x['case'],x['field_after'],x['end_pc'],x['setter_visited']) for x in experiments],flush=True)
 (HERE/'результат.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
