from pathlib import Path
import sys,hashlib,importlib.util,json,struct
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent; AN=P.parents[1];ROOT=AN.parent
sys.path.insert(0,str(AN/'инструменты'))
spec=importlib.util.spec_from_file_location('base',AN/'анализ_файла.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn import arm64_const as R
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
C=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);REG=[getattr(R,'UC_ARM64_REG_X%d'%i) for i in range(31)]
M=[dict(model='X-T5',file='FWUP0030.DAT',sha='790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',offsets=[0x300274,0x820274],bases=[0x1101000,0x28eb000],obj=0x2222248,field=0x108,start=0x14edccc,end=0x14edce8,getter=0x2f545ec,getter_end=0x2f545f8,helper=0x2eb2d40,helper_end=0x2eb2d58,writer=0x1558558, converter=0x14eaa38,save=0x25bcccc, snippets=[(0x14edccc,0x20),(0x14ee24c,0x10),(0x14eaa38,0x28),(0x1558550,0x24),(0x1543690,0x54),(0x15569c0,0x18),(0x2f545ec,0x10),(0x2eb2d40,0x18),(0x2eb2b54,0x68)]),dict(model='X100VI',file='FPUPDATE.DAT',sha='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',offsets=[0x9c02bc,0x10e02bc],bases=[0x11c1000,0x2b8f000],obj=0x230fa78,field=0x114,start=0x15c1524,end=0x15c1540,getter=0x3237ef0,getter_end=0x3237efc,helper=0x3193290,helper_end=0x31932a8,writer=0x1629628,converter=0x15bdf44,save=0x27f7a54,snippets=[(0x15c1524,0x20),(0x15c1aa4,0x10),(0x15bdf44,0x28),(0x1629620,0x24),(0x1613d94,0x54),(0x1627978,0x18),(0x3237ef0,0x10),(0x3193290,0x18),(0x31930a4,0x68)])]
def read32(uc,a):return struct.unpack('<I',uc.mem_read(a,4))[0]
def put32(uc,a,n):uc.mem_write(a,struct.pack('<I',n))
all_results=[]
for m in M:
 if m['model']=='X-T5':
  upstream=0x2d0820c; processor=0x14ed9b0
  m['snippets'] += [(0x14ed9b0,0x28),(0x2d0820c,0xf4),(0x15e24c0,0x50),(0x14f7338,0x24)]
 else:
  upstream=0x2fd1734; processor=0x15c11ec
  m['snippets'] += [(0x15c11ec,0x28),(0x2fd1734,0xf4),(0x16bd380,0x50),(0x15cac8c,0x24)]
 p=ROOT/'Firmware на прочиеFuji'/m['file'];raw=p.read_bytes();before=hashlib.sha256(raw).hexdigest();assert before==m['sha'];data=raw.translate(base.TRANSLATION)
 blocks=[]
 for j,(off,a) in enumerate(zip(m['offsets'],m['bases'])):
  b=base.unpack_fflz(data,off);assert struct.unpack_from('<Q',b,8)[0]==a
  if j+1<len(m['bases']):b=b[:m['bases'][j+1]-a]
  blocks.append((a,b))
 def snippet(addr,n):
  for a,b in blocks:
   if a<=addr and addr+n<=a+len(b):return [{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in C.disasm(b[addr-a:addr-a+n],addr)]
  raise ValueError(hex(addr))
 calls={hex(x):[] for x in (m['writer'],0x1543690 if m['model']=='X-T5' else 0x1613d94,upstream,processor)}
 for a,b in blocks:
  for o in range(0,len(b)-3,4):
   w=struct.unpack_from('<I',b,o)[0]
   if w>>26!=0x25:continue
   delta=w&0x3ffffff;delta=(delta-(1<<26) if delta&(1<<25) else delta)*4;target=hex(a+o+delta)
   if target in calls:calls[target].append(hex(a+o))
 experiments=[]
 for src,old in [(13,7),(13,13),(23,13),(255,13)]:
  uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(0x40000,0x5fc0000)
  for a,b in blocks:uc.mem_write(a,b)
  uc.mem_map(0x70000000,0x20000);sp=0x7000f000;source=0x70001000;obj=m['obj'];field=obj+m['field']
  put32(uc,field,old);put32(uc,source+0x144,src);uc.reg_write(R.UC_ARM64_REG_SP,sp);uc.reg_write(REG[19],obj);uc.reg_write(REG[20],source)
  visited=[]; mode_reads=[]
  def trace(uc,addr,size,user):
   if addr in (m['writer'],m['converter']):visited.append(hex(addr))
  def trace_read(uc,access,addr,size,value,user):
   if addr<m['save']+4 and addr+size>m['save']:mode_reads.append([hex(addr),size])
  uc.hook_add(UC_HOOK_MEM_READ,trace_read)
  uc.hook_add(UC_HOOK_CODE,trace);uc.emu_start(m['start'],m['end'],count=10000);assert uc.reg_read(R.UC_ARM64_REG_PC)==m['end'];after_write=read32(uc,field)
  uc.reg_write(REG[19],0xffff0000);uc.emu_start(m['getter'],m['getter_end'],count=10000);assert uc.reg_read(R.UC_ARM64_REG_PC)==m['getter_end'];getter_value=read32(uc,sp+0x60)
  uc.reg_write(REG[19],sp+0x60);uc.reg_write(REG[21],0xff);uc.reg_write(REG[24],0);uc.reg_write(REG[4],sp+0x60);put32(uc,sp+0x64,42)
  uc.emu_start(m['helper'],m['helper_end'],count=10000);assert uc.reg_read(R.UC_ARM64_REG_PC)==m['helper_end'];out=read32(uc,sp+0x6c)
  expected=src if src<=22 or src==255 else 0;assert (after_write,getter_value,out)==(expected,expected,42 if expected==255 else expected);assert not mode_reads
  experiments.append({'source_object':hex(source),'source_offset':'0x144','synthetic_source':src,'object':hex(obj),'field':hex(field),'synthetic_initial_field':old,'saved_mode_cell':hex(m['save']),'saved_mode_read_overlaps':mode_reads,'writer_fragment':[hex(m['start']),hex(m['end'])],'after_field':after_write,'visited':visited,'separate_getter_fragment':[hex(m['getter']),hex(m['getter_end'])],'artificial_handle':'0xffff0000','getter_stack_word':getter_value,'separate_computation_fragment':[hex(m['helper']),hex(m['helper_end'])],'artificial_w21':'0xff','artificial_table_result_w24':0,'artificial_second_word':42,'result_stack_word':out})
 after=hashlib.sha256(p.read_bytes()).hexdigest();assert after==before
 all_results.append({'model':m['model'],'dat':str(p.relative_to(ROOT)),'sha256_before':before,'sha256_after':after,'blocks':[{'dat_offset':hex(off),'base':hex(a),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for off,(a,b) in zip(m['offsets'],blocks)],'direct_bl':calls,'instructions':[{'start':hex(a),'code':snippet(a,n)} for a,n in m['snippets']],'experiments':experiments})
 print(m['model'],[(e['synthetic_source'],e['synthetic_initial_field'],e['after_field'],e['result_stack_word']) for e in experiments],flush=True)
(P/'альтернативный_источник.json').write_text(json.dumps(all_results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
