"""X100VI: execute candidate frame field and subsequent color preparation fragments."""
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
spec=importlib.util.spec_from_file_location('x100_frame_base',BASE/'анализ_файла.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
EXPECTED='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
SRC=ROOT/'Firmware на прочиеFuji/FPUPDATE.DAT'


def main():
 raw=SRC.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 d=raw.translate(base.TRANSLATION);a=base.unpack_fflz(d,0x9c02bc);b=base.unpack_fflz(d,0x10e02bc)
 ab=struct.unpack_from('<Q',a,8)[0];bb=struct.unpack_from('<Q',b,8)[0];assert ab==0x11c1000 and bb==0x2b8f000
 uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(ab,0x6000000-ab);uc.mem_write(ab,a);uc.mem_write(bb,b)
 uc.mem_map(0x60000000,0x20000);uc.mem_map(0x70000000,0x10000)
 frame,params,intermediate,context=0x60000000,0x60010000,0x60008000,0x6000c000
 def word(p):return struct.unpack('<I',uc.mem_read(p,4))[0]
 def fragment(start,end):
  uc.reg_write(UC_ARM64_REG_SP,0x7000f000);uc.emu_start(start,end,count=10000);assert uc.reg_read(UC_ARM64_REG_PC)==end
 results=[]
 for value,expected in [(0,0),(13,8),(18,9),(22,13)]:
  for addr in (frame,params,intermediate,context):uc.mem_write(addr,bytes(0x1000))
  uc.reg_write(UC_ARM64_REG_X0,frame);uc.reg_write(UC_ARM64_REG_X1,value);uc.reg_write(UC_ARM64_REG_X30,0x70000000)
  fragment(0x162a450,0x70000000)
  uc.reg_write(UC_ARM64_REG_X21,frame);uc.reg_write(UC_ARM64_REG_X20,params)
  fragment(0x30655fc,0x306560c)
  uc.reg_write(UC_ARM64_REG_X20,params);uc.reg_write(UC_ARM64_REG_X19,intermediate)
  fragment(0x2ffa690,0x2ffa698)
  uc.reg_write(UC_ARM64_REG_X20,intermediate);uc.reg_write(UC_ARM64_REG_X19,context)
  fragment(0x31501c0,0x31501d4)
  row={'input':value,'frame_d0':word(frame+0xd0),'params_3fe8':word(params+0x3fe8),'intermediate_20':word(intermediate+0x20),'context_130':word(context+0x130)}
  assert [row['frame_d0'],row['params_3fe8'],row['intermediate_20'],row['context_130']]==[value,value,value,expected]
  results.append(row)
 assert hashlib.sha256(SRC.read_bytes()).hexdigest()==EXPECTED
 result={'source_sha256':EXPECTED,'source_unchanged':True,'fragments':['0x162a450..return','0x30655fc..0x306560c','0x2ffa690..0x2ffa698','0x31501c0..0x31501d4'],'results':results,'limits':['Synthetic initial value is passed to frame setter by investigator; no global state to frame bridge proven.','Separate fragments started by investigator; condition before 0x2ffa690 not executed.','No real camera or image hardware.']}
 (HERE/'Кадр_переходы.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
