"""Execute the parameter conversion function separately for all four images."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / 'инструменты'))
spec = importlib.util.spec_from_file_location('firmware_tables', HERE/'сопоставить_таблицы.py')
tables = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tables)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

# Absolute addresses belong to the particular image and memory mapping.
CONFIG = {
 'X-H2': (0x12e67ac,1678,0x2051000,0x408),
 'X-H2S': (0x1604da0,1677,0x236b000,0x408),
 'X-T5': (0x12e48b0,1699,0x2000000,0x7ec),
 'X100VI': (0x13c9930,1756,0x20b4000,0x4c4),
}

def main():
 result={}
 for model,(func,parameter,error_page,error_offset) in CONFIG.items():
  rel,sha,ao,bo,table,keypos,template,gainpos=tables.FILES[model]
  path=ROOT/rel;raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==sha
  block=tables.base.unpack_fflz(raw.translate(tables.base.TRANSLATION),ao)
  address=struct.unpack_from('<Q',block,8)[0];length=(len(block)+4095)&~4095
  uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(address,length);uc.mem_write(address,block)
  if not address <= error_page < address+length:
   uc.mem_map(error_page,0x1000)
  uc.mem_map(0x70000000,0x10000)
  cases=[]
  for value in range(27):
   uc.mem_write(error_page+error_offset,bytes(4))
   for reg,val in [(UC_ARM64_REG_X0,parameter),(UC_ARM64_REG_X1,value),(UC_ARM64_REG_X2,0),(UC_ARM64_REG_X3,3),(UC_ARM64_REG_X30,0x70000000),(UC_ARM64_REG_SP,0x7000f000)]:
    uc.reg_write(reg,val)
   uc.emu_start(func,0x70000000,count=10000)
   assert uc.reg_read(UC_ARM64_REG_PC)==0x70000000
   cases.append({'input_ui_code':value,'result':uc.reg_read(UC_ARM64_REG_X0)&0xffffffff,'error':struct.unpack('<I',uc.mem_read(error_page+error_offset,4))[0]})
  assert cases[14]['result']==13 and cases[14]['error']==0
  assert cases[26]['error']==1
  assert hashlib.sha256(path.read_bytes()).hexdigest()==sha
  result[model]={'source_sha256':sha,'function_address':hex(func),'parameter_id':parameter,'input_representation':0,'output_representation':3,'error_address':hex(error_page+error_offset),'cases':cases,'source_unchanged':True}
 (HERE/'Перевод_имитаций_исполнение.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({model:{'address':r['function_address'],'parameter':r['parameter_id'],'ui14':r['cases'][14],'ui25':r['cases'][25],'ui26':r['cases'][26]} for model,r in result.items()},ensure_ascii=False,indent=2))

if __name__=='__main__':
 main()
