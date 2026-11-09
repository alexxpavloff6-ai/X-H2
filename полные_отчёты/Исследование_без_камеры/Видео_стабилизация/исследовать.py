"""Изолированные AArch64-фрагменты: только чтение DAT, искусственные регистры и память."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

P = Path(__file__).resolve().parent
FW = P.parents[1]
ROOT = FW.parent
sys.path.insert(0, str(FW / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', FW / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X22, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

MODELS = {
 'X-H2': ('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274],0x117ea38,0x118001c,0x11835c0,0x12eeb00,0x26804f4,0x2c8b634),
 'X-H2S': ('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],0x149dea4,0x149f488,0x14a2a2c,0x160d018,0x299c4ec,0x2fa35d0),
 'X-T5': ('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],0x117f0ec,0x11806d0,0x1183c74,0x12eccc0,0x25bcda8,0x2bcaef8),
 'X100VI': ('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],0x123f688,0x1240c98,0x1244654,0x13d1b80,0x27f7b34,0x2e8c6a8),
}
# reader ADRP, common return-load, wrapper, converter, pointer table, key, error flag, stack offset
READERS = {
 'X-H2': (0x2c97238,0x2c940b8,0x1135930,0x12e67ac,0x1bd5ab8,0x11,0x2051408,0x10c),
 'X-H2S': (0x2faef94,0x2fabe14,0x1455930,0x1604da0,0x1ef1aa8,0x11,0x236b408,0x10c),
 'X-T5': (0x2bd8eb4,0x2bd5d78,0x1135948,0x12e48b0,0x1bb1a30,0x12,0x20007ec,0x8c),
 'X100VI': (0x2e9ae40,0x2e97ca4,0x11f5a34,0x13c9930,0x1c60a50,0x11,0x20b44c4,0x7c),
}
C = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def sha(data): return hashlib.sha256(data).hexdigest()
def hx(n): return hex(n)
def dis(buf, addr, start, size):
 return [f'{i.address:#x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in C.disasm(buf[start-addr:start-addr+size], start)]
def text_at(uc, addr):
 if not addr: return None
 out=bytearray()
 while len(out)<256:
  c=bytes(uc.mem_read(addr+len(out),1))
  if c==b'\0': return out.decode('ascii')
  out.extend(c)
 raise ValueError('unterminated string')
def uc_new(blocks):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 u.mem_map(0x1000000,0x5000000)
 for addr,b in blocks: u.mem_write(addr,b)
 u.mem_map(0x70000000,0x10000)
 u.reg_write(UC_ARM64_REG_SP,0x7000f000)
 return u

def main():
 result={'method':'Unicorn AArch64; RAM и входы искусственные; источник read-only','models':{}}
 for name,(rel,expected,offsets,is_entry,shutter_entry,movie_entry,setter,state,caller) in MODELS.items():
  path=ROOT/rel;raw=path.read_bytes();before=sha(raw)
  if before != expected: raise ValueError(f'{name}: unexpected input hash {before}')
  translated=raw.translate(base.TRANSLATION)
  blocks=[]
  for off in offsets:
   b=base.unpack_fflz(translated,off); blocks.append((struct.unpack_from('<Q',b,8)[0],b))
  a,b=blocks[0]; tables={}
  # These are independent string->integer pairs in the second unpacked block, not camera settings.
  a2,b2=blocks[1]
  for prefix in ('UI_BLURRING_CORRECT_MODE_', 'UI_BLURRING_MOVIE_', 'UI_SHUTTER_TYPE_', 'MODE_BLURRING_STRENGTH_', 'UI_MENUCOM_ITEM_BLURRING', 'UI_MENUCOM_ITEM_BLUR_CORRECTION_MOVIE'):
   found=[]
   import re
   for match in re.finditer(re.escape(prefix.encode())+rb'[A-Z0-9_]*\x00',b2):
    pointer=struct.pack('<Q',a2+match.start()); pos=b2.find(pointer)
    if pos>=0 and pos+16<=len(b2):
     found.append({'name':match.group()[:-1].decode(),'string_offset':hx(match.start()),'pair_offset':hx(pos),'value':struct.unpack_from('<Q',b2,pos+8)[0]})
   tables[prefix]=found
  u=uc_new(blocks)
  # The strength setter's diagnostic branch calls a value-to-name consumer twice.
  ins=list(C.disasm(b[setter-a+0x68:setter-a+0x6c],setter+0x68))
  assert len(ins)==1 and ins[0].mnemonic=='bl'
  decoder=int(ins[0].op_str.lstrip('#'),16)
  decoders={}
  for key,entry,values in [('is_mode',is_entry,list(range(12))),('shutter_type',shutter_entry,list(range(13))),('movie_is',movie_entry,list(range(9))),('strength',decoder,[0,1,2,3,0xffffffff])]:
   rows=[]
   for value in values:
    u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_X30,0x70000000)
    u.emu_start(entry,0x70000000,count=200)
    assert u.reg_read(UC_ARM64_REG_PC)==0x70000000
    ptr=u.reg_read(UC_ARM64_REG_X0)
    rows.append({'input':value,'returned_pointer':hx(ptr),'returned_string':text_at(u,ptr)})
   decoders[key]={'entry':hx(entry),'results':rows}
  experiments=[]
  for value,initial in [(0,1),(1,0),(1,1),(0xdeadbeef,0)]:
   vm=uc_new(blocks);vm.mem_write(state,struct.pack('<I',initial))
   vm.reg_write(UC_ARM64_REG_X22,value); visited=[]
   def trace(uc,pc,size,data):
    if pc==setter: visited.append(hx(pc))
   vm.hook_add(UC_HOOK_CODE,trace)
   vm.emu_start(caller,caller+8,count=200)
   assert vm.reg_read(UC_ARM64_REG_PC)==caller+8 and visited==[hx(setter)]
   after=struct.unpack('<I',vm.mem_read(state,4))[0]
   experiments.append({'entry':hx(caller),'stop':hx(caller+8),'synthetic_w22':hx(value),'synthetic_initial_word':hx(initial),'visited':visited,'final_word':hx(after)})
  # Direct BL scan covers aligned words in both complete decompressed blocks; data may resemble instructions.
  calls=[]
  for start,buf in blocks:
   for off in range(0,len(buf)-3,4):
    w=struct.unpack_from('<I',buf,off)[0]
    if w>>26 != 0x25: continue
    delta=w&0x3ffffff
    if delta&(1<<25): delta-=1<<26
    if start+off+4*delta==setter:
     pc=start+off
     calls.append({'address':hx(pc),'context':dis(buf,start,pc-0x18,0x24)})
  reader,retload,wrapper,converter,pt,key,error,stackoff=READERS[name]
  table=struct.unpack_from('<Q',b,pt-a+key*8)[0]
  rows=[list(struct.unpack_from('<IIII',b,table-a+16*i)) for i in range(3)]
  reader_runs=[]
  for value,initial in [(0,1),(1,0),(1,1),(2,0),(0xdeadbeef,0)]:
   vm=uc_new(blocks)
   vm.mem_write(state,struct.pack('<I',initial))
   vm.mem_write(error,struct.pack('<I',0xa5))
   vm.reg_write(UC_ARM64_REG_X22,value)
   trace_data=[]
   def trace_consumer(uc,pc,size,data):
    if pc in (setter,wrapper,converter):
     trace_data.append({'pc':hx(pc),'w0':hx(uc.reg_read(UC_ARM64_REG_X0)&0xffffffff),'w1':hx(uc.reg_read(UC_ARM64_REG_X1)&0xffffffff),'w2':hx(uc.reg_read(UC_ARM64_REG_X2)&0xffffffff),'w3':hx(uc.reg_read(UC_ARM64_REG_X3)&0xffffffff)})
   vm.hook_add(UC_HOOK_CODE,trace_consumer)
   vm.emu_start(caller,caller+8,count=200)
   assert vm.reg_read(UC_ARM64_REG_PC)==caller+8
   stored=struct.unpack('<I',vm.mem_read(state,4))[0]
   # Enter the independently located reader directly, in the SAME VM; no state copy.
   vm.emu_start(reader-8,retload+4,count=10000)
   assert vm.reg_read(UC_ARM64_REG_PC)==retload+4
   word=struct.unpack('<I',vm.mem_read(0x7000f000+stackoff,4))[0]
   returned=vm.reg_read(UC_ARM64_REG_X0)&0xffffffff
   flag=struct.unpack('<I',vm.mem_read(error,4))[0]
   assert [x['pc'] for x in trace_data]==list(map(hx,(setter,wrapper,converter)))
   reader_runs.append({'synthetic_w22':hx(value),'initial_state':hx(initial),'stored_state':hx(stored),'reader_entry':hx(reader-8),'return_load':hx(retload),'stack_word':hx(word),'return_w0':hx(returned),'initial_error_flag':'0xa5','final_error_flag':hx(flag),'state_copied_by_researcher':False,'trace':trace_data})
  accesses=[]
  for start,buf in blocks:
   for off in range(0,len(buf)-8,4):
    w=struct.unpack_from('<I',buf,off)[0]
    if w&0x9f000000!=0x90000000: continue
    imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2)
    if imm&(1<<20): imm-=1<<21
    if ((start+off)&~0xfff)+(imm<<12)!=state&~0xfff: continue
    pair=list(C.disasm(buf[off:off+8],start+off))
    if len(pair)==2 and pair[1].mnemonic in ('ldr','str') and pair[1].op_str.endswith(f'#0x{state&0xfff:x}]') and pair[1].op_str.split('[')[-1].split(',')[0]==pair[0].op_str.split(',')[0]:
     accesses.append({'address':hx(start+off),'instructions':dis(buf,start,start+off,8)})
  reader_result={'state_access_search':'both full unpacked blocks, aligned ADRP immediately followed by LDR/STR using same base and exact page offset; does not cover other address constructions','accesses':accesses,'reader_instructions':dis(b2,a2,reader-8,0x20),'return_instructions':dis(b2,a2,retload,0x10),'wrapper_instructions':dis(b,a,wrapper,0x14),'converter_instructions':dis(b,a,converter,0x140),'pointer_table':hx(pt),'key':key,'selected_table':hx(table),'table_rows_32bit':rows,'error_virtual_address':hx(error),'runs':reader_runs}
  after_hash=sha(path.read_bytes())
  assert after_hash==before
  result['models'][name]={'source':rel,'sha256_before':before,'sha256_after':after_hash,'blocks':[{'packed_offset':hx(off),'virtual_base':hx(addr),'bytes':len(buf),'sha256':sha(buf)} for off,(addr,buf) in zip(offsets,blocks)],'dictionary':tables,'decoders':decoders,'setter':hx(setter),'state_virtual_address':hx(state),'setter_instructions':dis(b,a,setter,0x98),'decoder_instructions':dis(b,a,decoder,0x38),'direct_bl_candidates':calls,'direct_bl_search':'each aligned 32-bit word in both complete unpacked blocks; includes data false positives','caller_to_setter_experiments':experiments}
  result['models'][name]['state_reader_to_return']=reader_result
 out=P/'результаты.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({n:{'strength':v['decoders']['strength']['results'],'calls':len(v['direct_bl_candidates']),'experiments':v['caller_to_setter_experiments']} for n,v in result['models'].items()},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
