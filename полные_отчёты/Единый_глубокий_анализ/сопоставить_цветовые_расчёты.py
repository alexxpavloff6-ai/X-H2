"""Execute real firmware color selector and coefficient calculations in Unicorn.

Synthetic state; base settings image from each file. Not a whole-camera run.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
sys.path.insert(0,str(HERE.parent/'инструменты'))
spec=importlib.util.spec_from_file_location('camera_table_inputs',HERE/'сопоставить_таблицы.py')
tables=importlib.util.module_from_spec(spec);spec.loader.exec_module(tables)
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC

CONFIG={
 'X-H2': (0x2f24284,0x2f24680,0x20c1458),
 'X-H2S': (0x323b004,0x323b400,0x23dbc30),
 'X-T5': (0x2e5f410,0x2e5f7dc,0x2066d90),
 'X100VI': (0x313a1c0,0x313a590,0x211c1c8),
}


def run(uc,pc,args):
 uc.reg_write(UC_ARM64_REG_X0,args[0]);uc.reg_write(UC_ARM64_REG_X1,args[1])
 uc.reg_write(UC_ARM64_REG_X30,0x70000000);uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
 uc.emu_start(pc,0x70000000,count=100000)
 assert uc.reg_read(UC_ARM64_REG_PC)==0x70000000


def main():
 results={}
 for model,(selector,calc,pointer) in CONFIG.items():
  rel,sha,ao,bo,table,keypos,template,gainpos=tables.FILES[model]
  path=ROOT/rel;raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==sha
  data=raw.translate(tables.base.TRANSLATION)
  a=tables.base.unpack_fflz(data,ao);b=tables.base.unpack_fflz(data,bo)
  aa=struct.unpack_from('<Q',a,8)[0];bb=struct.unpack_from('<Q',b,8)[0]
  assert aa<bb<0x6000000 and bb+len(b)<0x6000000
  uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
  # One shared region correctly handles overlapping zero-padded image ranges.
  uc.mem_map(aa,0x6000000-aa);uc.mem_write(aa,a);uc.mem_write(bb,b)
  uc.mem_map(0x27008000,0x100000)
  uc.mem_write(0x27008000,data[template:template+0xc6c00])
  uc.mem_write(pointer,struct.pack('<Q',0x27008000))
  uc.mem_map(0x60000000,0x20000);uc.mem_map(0x70000000,0x10000)
  src,out=0x60000000,0x60010000
  context={0x100:0,0x12c:1,0x130:8,0x124:0x12,0x128:0x12,0x13c:4,0x10c:8,0x17c:2}
  for offset,value in context.items():uc.mem_write(src+offset,struct.pack('<I',value))
  run(uc,selector,[src,out]);selected=bytes(uc.mem_read(out,1))[0];assert selected==6
  keys=struct.unpack_from('<4I',b,keypos)
  source=[tables.signed13(struct.unpack_from('<H',data,template+k)[0]) for k in keys]
  in_output_order=[source[0],source[2],source[1],source[3]]
  gains=list(data[template+gainpos:template+gainpos+9])
  runs=[]
  for index,gain in enumerate(gains):
   uc.mem_write(src+0x13c,struct.pack('<I',index));uc.mem_write(out,bytes(0x1000))
   run(uc,calc,[src,out]);actual=list(struct.unpack('<4h',uc.mem_read(out+0x3c,8)))
   expected=[max(-4096,min(4095,(value*gain*128*64)>>20)) for value in in_output_order]
   assert actual==expected,(model,index,actual,expected)
   runs.append({'input_index':index,'gain_byte':gain,'four_output_signed':actual})
  assert hashlib.sha256(path.read_bytes()).hexdigest()==sha
  results[model]={'source_sha256':sha,'selector_address':hex(selector),'calculation_address':hex(calc),'template_pointer_storage':hex(pointer),'template_dat_offset':hex(template),'synthetic_context':{hex(k):v for k,v in context.items()},'selector_output':selected,'selected_key_offsets':[hex(k) for k in keys],'four_template_values_signed_in_table_order':source,'input_runs':runs,'source_unchanged':True}
 (HERE/'Цветовые_расчёты_исполнение.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({m:{'selector':r['selector_output'],'index_4':r['input_runs'][4]['four_output_signed'],'index_6':r['input_runs'][6]['four_output_signed']} for m,r in results.items()},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
