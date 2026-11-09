"""Поиск шаблонов и исполнение сравнителя в изолированной ARM64 VM. DAT только читаются."""
from pathlib import Path
import sys, struct, hashlib, importlib.util, json
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AN = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('unpack', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_SP, UC_ARM64_REG_PC

MODELS = [
 ('X-H2 5.30','FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274],[0x1101000,0x29ae000]),
 ('X-H2S 7.30','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],[0x1421000,0x2cca000]),
 ('X-T5 4.31','Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],[0x1101000,0x28eb000]),
 ('X100VI 1.31','Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],[0x11c1000,0x2b8f000]),
]
def hx(v): return hex(int(v))
PIPE = {
 'X-H2 5.30': (0x2cd83b8,0x2cd863c,0x38f4318,0x38f44a0,0x38f44b0,0x2cd8448),
 'X-H2S 7.30': (0x2ff01d0,0x2ff0454,0x3b6e258,0x3b6e3e0,0x3b6e3f0,0x2ff0260),
 'X-T5 4.31': (0x2c1850c,0x2c18790,0x381c2c8,0x381c450,0x381c460,0x2c1859c),
 'X100VI 1.31': (0x2edb924,0x2edbb70,0x4145540,0x41456c8,0x41456d8,0x2edb9b0),
}
FUNCTION = {'X-H2 5.30':0x2cd8350,'X-H2S 7.30':0x2ff0168,'X-T5 4.31':0x2c184a4,'X100VI 1.31':0x2edb8c0}
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def sha(b): return hashlib.sha256(b).hexdigest()
def code(blocks, start, length):
 for addr, buf in blocks:
  if addr <= start and start+length <= addr+len(buf):
   return [f'{i.address:#010x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in cs.disasm(buf[start-addr:start-addr+length], start)]
 raise ValueError(hex(start))
def main():
 results=[]
 for name,filename,expected,offsets,starts in MODELS:
  path=ROOT/filename; raw=path.read_bytes(); before=sha(raw); assert before==expected
  decoded=raw.translate(base.TRANSLATION); blocks=[]
  for off,addr in zip(offsets,starts):
   buf=base.unpack_fflz(decoded,off); assert struct.unpack_from('<Q',buf,8)[0]==addr
   blocks.append((addr,buf))
  # Последний загруженный блок имеет приоритет, как в предыдущих исследованиях.
  regions=[]
  for j,(addr,buf) in enumerate(blocks):
   n=min(len(buf),starts[j+1]-addr) if j+1<len(blocks) else len(buf)
   regions.append((addr,buf[:n]))
  found={}
  for ext in ('JPG','RAF','HIF'):
   needle=('\\DSCF0000.'+ext).encode()+b'\0'
   matches=[]
   for addr,buf in regions:
    p=0
    while True:
     p=buf.find(needle,p)
     if p<0: break
     matches.append(addr+p);p+=1
   assert len(matches)==1,(name,ext,matches)
   target=matches[0]; refs=[]
   for addr,buf in regions:
    w=np.frombuffer(buf[:len(buf)//4*4],dtype='<u4')
    ids=np.nonzero((w & 0x9f000000)==0x90000000)[0]
    pc=addr+ids*4; imm=(((w[ids]>>29)&3)|(((w[ids]>>5)&0x7ffff)<<2)).astype('int64'); imm[imm & (1<<20)!=0]-=1<<21
    pages=(pc & ~4095)+(imm<<12)
    for idx in ids[pages==(target & ~4095)]:
     reg=int(w[idx]&31)
     for j in range(1,9):
      if idx+j>=len(w): break
      v=int(w[idx+j])
      if v&0xffc00000==0x91000000 and (v>>5)&31==reg and (v>>10)&0xfff==target&0xfff:
       refs.append(addr+int(idx)*4)
   found[ext]={'template_address':hx(target),'template_bytes_hex':needle.hex(),'adrp_add_refs':[hx(x) for x in refs]}
   assert len(refs)==1,(name,ext,refs)
   ref=refs[0]; lines=code(regions,ref-4,24); found[ext]['instructions']=lines
   # mov w2,14; adrp/add x1; mov x0,x21; bl comparator; cbz/cbnz.
   assert 'mov w2, #0xe' in lines[0] and 'mov x0, x21' in lines[3] and ' bl ' in lines[4] and ('cbz x0' in lines[5] or 'cbnz x0' in lines[5]),(name,ext,lines)
   cases=[]
   for variant in ('exact','wrong_extension','wrong_digit'):
    data=bytearray(needle)
    if variant=='wrong_extension': data[-2]=ord('X')
    if variant=='wrong_digit': data[5]=ord('1')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
    for a,buf in regions: u.mem_write(a,buf)
    u.mem_map(0x70000000,0x10000);u.mem_write(0x70001000,bytes(data))
    u.reg_write(UC_ARM64_REG_X21,0x70001000);u.reg_write(UC_ARM64_REG_SP,0x7000f000)
    u.emu_start(ref-4,ref+16,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==ref+16
    value=u.reg_read(UC_ARM64_REG_X0);u.emu_start(ref+16,0,count=1);dest=u.reg_read(UC_ARM64_REG_PC)
    assert (value==0)==(variant=='exact')
    cases.append({'input_hex':bytes(data).hex(),'variant':variant,'comparator_x0':hx(value),'branch_pc_after':hx(dest)})
   found[ext]['vm_cases']=cases
   found[ext]['context_before']=code(regions,ref-0xb0,0xb0)
   found[ext]['context_after']=code(regions,ref+16,0xc0)
  # Единый непрерывный фрагмент: поля структуры, проверка имени, копирование.
  start,copycall,dst,limit1,limit2,reject=PIPE[name]
  mismatch=int(found['RAF']['vm_cases'][1]['branch_pc_after'],16)
  flow=[]
  for ext,typ,variant,flag in [('JPG',0x3801,'exact',0),('RAF',0x380d,'exact',0),('HIF',0x3812,'exact',0),('RAF',0x380d,'wrong_digit',0),('RAF',0x380d,'exact',1)]:
   obj=bytearray((i*17+3)&255 for i in range(0x58))
   struct.pack_into('<II',obj,0x30,typ,flag)
   filename_bytes=bytearray(('\\DSCF0000.'+ext).encode()+b'\0')
   if variant=='wrong_digit': filename_bytes[5]=ord('1')
   obj[:len(filename_bytes)]=filename_bytes
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
   for a,buf in regions: u.mem_write(a,buf)
   u.mem_map(0x70000000,0x10000)
   u.mem_write(0x70002000,bytes(obj))
   u.mem_write(dst,bytes([0xa5])*0x58)
   u.mem_write(limit1,bytes(4));u.mem_write(limit2,bytes(4))
   u.reg_write(UC_ARM64_REG_X20,0x70002000);u.reg_write(UC_ARM64_REG_X21,0x70002000);u.reg_write(UC_ARM64_REG_SP,0x7000f000)
   seen=[]
   def stop(uc,addr,size,user):
    if addr in (copycall+4,mismatch,reject):
     seen.append(addr);uc.emu_stop()
   u.hook_add(UC_HOOK_CODE,stop)
   u.emu_start(start,0,count=10000)
   assert seen,(name,ext,variant,flag,hex(u.reg_read(UC_ARM64_REG_PC)))
   actual=bytes(u.mem_read(dst,0x58));copied=actual==bytes(obj)
   assert copied==(variant=='exact' and flag==0),(name,ext,variant,flag,hx(seen[0]))
   flow.append({'ext':ext,'object_type_at_0x30':hx(typ),'object_flag_at_0x34':flag,'filename_hex':bytes(filename_bytes).hex(),'object_hex':bytes(obj).hex(),'destination_initial_hex':(bytes([0xa5])*0x58).hex(),'destination_final_hex':actual.hex(),'stopped_at':hx(seen[0]),'copied_0x58_bytes':copied})
  object_flow={'start':hx(start),'copy_call':hx(copycall),'destination':hx(dst),'zeroed_limit_words':[hx(limit1),hx(limit2)],'mismatch_stop':hx(mismatch),'nonzero_flag_stop':hx(reject),'experiments':flow}
  # Контекст на уровне имён — поисковый ориентир, не установление типа обработчика.
  names={}
  for term in (b'recbjpeg',b'recblsraw',b'recbmedia'):
   hits=[]
   for addr,buf in regions:
    p=0
    while True:
     p=buf.find(term+b'\0',p)
     if p<0: break
     hits.append(hx(addr+p));p+=1
   names[term.decode()]=hits
  fn=FUNCTION[name]; pointers=[]; direct_calls=[]; protocol_strings={}
  for addr,buf in regions:
   p=0
   while True:
    p=buf.find(struct.pack('<Q',fn),p)
    if p<0: break
    pointers.append({'address':hx(addr+p),'surrounding_bytes_hex':buf[p-48:p+64].hex()});p+=1
   words=np.frombuffer(buf[:len(buf)//4*4],dtype='<u4')
   ids=np.nonzero((words>>26)==0x25)[0]
   delta=(words[ids]&0x3ffffff).astype('int64');delta[delta&0x2000000!=0]-=0x4000000
   pc=addr+ids*4
   direct_calls.extend(hx(v) for v in pc[pc+delta*4==fn])
  for term in (b'SYS_USB_MODE_MTP',b'WIFI_PTP_CONNECT',b'>> ptp_connect()'+bytes((13,10)),b'PTP_XXX'):
   hits=[]
   for addr,buf in regions:
    p=buf.find(term+b'\0')
    if p>=0: hits.append(hx(addr+p))
   protocol_strings[term.decode()]=hits
  context={'function_entry':hx(fn),'entry_instructions':code(regions,fn,start-fn),'little_endian_pointer_hits':pointers,'direct_bl_hits':direct_calls,'protocol_string_addresses':protocol_strings}
  after=sha(path.read_bytes()); assert after==before
  results.append({'model':name,'input_path':filename,'sha256_before':before,'sha256_after':after,'blocks':[{'dat_offset':hx(off),'base':hx(a),'size':len(b),'sha256':sha(b)} for off,(a,b) in zip(offsets,blocks)],'filename_templates':found,'object_flow':object_flow,'caller_context':context,'task_name_string_addresses':names})
 (HERE/'результаты.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps([{ 'model':r['model'],'templates':{k:{'address':v['template_address'],'refs':v['adrp_add_refs'],'cases':v['vm_cases']} for k,v in r['filename_templates'].items()}} for r in results],ensure_ascii=False,indent=2))
if __name__=='__main__': main()
