"""X-H2: execute actual change branch, color conversion and coefficient preparation.

Synthetic global values; does not execute physical button, display or image hardware.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE=Path(__file__).resolve().parent
BASE=HERE.parent.parent
ROOT=BASE.parent
sys.path.insert(0,str(BASE/'инструменты'))
spec=importlib.util.spec_from_file_location('xh2_trace_base',BASE/'анализ_файла.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC

EXPECTED='be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203'
SRC=ROOT/'FIRMWARE/ver 5.30/FWUP0028.DAT'


def main():
 raw=SRC.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 data=raw.translate(base.TRANSLATION);a=base.unpack_fflz(data,0x300274);b=base.unpack_fflz(data,0x840274)
 uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(0x1101000,0x6000000-0x1101000);uc.mem_write(0x1101000,a);uc.mem_write(0x29ae000,b)
 uc.mem_map(0x27008000,0x100000);uc.mem_write(0x27008000,data[0xc0274:0xc0274+0xc6c00]);uc.mem_write(0x20c1458,struct.pack('<Q',0x27008000))
 uc.mem_map(0x60000000,0x20000);uc.mem_map(0x70000000,0x10000)
 def put32(addr,value):uc.mem_write(addr,struct.pack('<I',value&0xffffffff))
 def get32(addr):return struct.unpack('<I',uc.mem_read(addr,4))[0]
 def call(entry,args):
  for reg,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3),args):uc.reg_write(reg,value)
  uc.reg_write(UC_ARM64_REG_X30,0x70000000);uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
  uc.emu_start(entry,0x70000000,count=100000);assert uc.reg_read(UC_ARM64_REG_PC)==0x70000000
  return uc.reg_read(UC_ARM64_REG_X0)&0xffffffff
 changes=[];stop=[];visited=[]
 def hook(machine,address,size,user):
  if address in (0x132d5d8,0x1135930,0x12e67ac,0x12eefc0):visited.append(hex(address))
  if address in (0x132d150,0x132d5e0):stop.append(address);machine.emu_stop()
 handle=uc.hook_add(UC_HOOK_CODE,hook)
 for new,old in [(0,1),(14,0),(17,0),(18,0),(14,14)]:
  put32(0x2053f70,new);put32(0x2051c90,old);put32(0x2680414,0xaaaaaaaa);put32(0x2051408,0)
  uc.reg_write(UC_ARM64_REG_SP,0x7000f000);stop.clear();visited.clear()
  uc.emu_start(0x132d138,0,count=10000)
  assert len(stop)==1
  expected={0:0,14:13,17:22,18:18}[new] if new!=old else 0xaaaaaaaa
  assert get32(0x2680414)==expected
  assert get32(0x2051408)==0
  fragment_trace=visited[:]
  representation=None
  if new!=old:
   # A separate existing consumer reads exactly the state just written; no manual copy.
   uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
   uc.emu_start(0x2bfacf8,0x2bfad10,count=10000)
   assert uc.reg_read(UC_ARM64_REG_PC)==0x2bfad10
   representation=uc.reg_read(UC_ARM64_REG_X0)&0xffffffff
   assert representation=={0:1,14:11,17:20,18:16}[new]
   assert get32(0x2051408)==0
  changes.append({'new_word':new,'compared_word':old,'state':get32(0x2680414),'stop':hex(stop[0]),'visited':fragment_trace,'separate_consumer_output':representation})
 uc.hook_del(handle)
 # Execute separate real fragments in one synthetic memory; state->frame is supplied.
 frame,params,intermediate,context=0x60000000,0x60010000,0x60008000,0x6000c000
 frames=[]
 for mode,expected_color in [(0,0),(13,8),(18,9),(22,13)]:
  for addr in (frame,params,intermediate,context):uc.mem_write(addr,bytes(0x1000))
  call(0x1562e18,[frame,mode])
  uc.reg_write(UC_ARM64_REG_X21,frame);uc.reg_write(UC_ARM64_REG_X20,params);uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
  uc.emu_start(0x2e57320,0x2e57330,count=10000);assert uc.reg_read(UC_ARM64_REG_PC)==0x2e57330
  uc.reg_write(UC_ARM64_REG_X20,params);uc.reg_write(UC_ARM64_REG_X19,intermediate)
  uc.emu_start(0x2df1758,0x2df1760,count=10000);assert uc.reg_read(UC_ARM64_REG_PC)==0x2df1760
  uc.reg_write(UC_ARM64_REG_X20,intermediate);uc.reg_write(UC_ARM64_REG_X19,context)
  uc.emu_start(0x2f39e64,0x2f39e70,count=10000);assert uc.reg_read(UC_ARM64_REG_PC)==0x2f39e70
  row={'mode':mode,'frame_c0':get32(frame+0xc0),'params_39b8':get32(params+0x39b8),'intermediate_20':get32(intermediate+0x20),'color_130':get32(context+0x130)}
  assert list(row.values())==[mode,mode,mode,mode,expected_color]
  frames.append(row)
 color_table=struct.unpack_from('<Q',a,0x1bd5ab8-0x1101000+1715*8)[0]
 assert color_table==0x176d7b0
 ui=[];src=0x60000000;out=0x60010000
 for code in range(9):
  field=struct.unpack_from('<4I',a,color_table-0x1101000+16*code)
  repr10=field[3] if field[3]<0x80000000 else field[3]-(1<<32)
  put32(0x2051408,0);native=call(0x12e67ac,[1715,code,0,3]);assert get32(0x2051408)==0
  uc.mem_write(out,bytes(0x1000));call(0x2f390bc,[out,native,1,0]);idx=get32(out)
  assert native==code and idx==8-code
  uc.mem_write(src,bytes(0x1000));uc.mem_write(out,bytes(0x1000))
  for offset,value in {0x100:0,0x12c:1,0x130:8,0x124:0x12,0x128:0x12,0x13c:idx,0x10c:8,0x17c:2}.items():put32(src+offset,value)
  call(0x2f24680,[src,out]);coefs=struct.unpack('<4h',uc.mem_read(out+0x3c,8))
  ui.append({'ui_enum':code,'representation_div10':repr10/10,'native':native,'index':idx,'coefficients':list(coefs)})
 assert ui[2]['representation_div10']==2 and ui[2]['coefficients']==[974,-12,946,-14]
 assert ui[4]['representation_div10']==0 and ui[4]['coefficients']==[885,-10,859,-12]
 assert hashlib.sha256(SRC.read_bytes()).hexdigest()==EXPECTED
 result={'source_sha256':EXPECTED,'source_unchanged':True,'change_fragment':'0x132d138','compared_addresses':['0x2053f70','0x2051c90'],'state_address':'0x2680414','change_cases':changes,'frame_fragments':frames,'color_parameter_id':1715,'color_table_address':hex(color_table),'color_cases':ui,'limits':['Values of compared global words are synthetic; physical input and actual provenance not observed.','The investigator manually supplies MODE to the frame setter and starts separate fragments; no state-to-frame bridge proven.','Color state and film branch are connected by the investigator using results; not one continuous camera run.','Camera hardware and output image not executed.']}
 (HERE/'выбор_и_цвет.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'change_cases':changes,'color_0':ui[4],'color_plus2':ui[2],'source_unchanged':True},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
