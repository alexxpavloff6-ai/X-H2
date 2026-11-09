"""X100VI 1.31: извлечение в памяти, статический анализ и Unicorn; DAT только чтение."""
from pathlib import Path
import sys, importlib.util, hashlib, struct, json, csv
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'Firmware на прочиеFuji'/'FPUPDATE.DAT').exists())
AN=ROOT/'Анализ_прошивки'; sys.path.insert(0,str(AN/'инструменты'))
spec=importlib.util.spec_from_file_location('decoder',AN/'анализ_файла.py'); decoder=importlib.util.module_from_spec(spec); spec.loader.exec_module(decoder)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_LR, UC_ARM64_REG_PC
src=ROOT/'Firmware на прочиеFuji'/'FPUPDATE.DAT'; raw=src.read_bytes(); digest=hashlib.sha256(raw).hexdigest()
assert digest=='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
dat=raw.translate(decoder.TRANSLATION); b=decoder.unpack_fflz(dat,0x9c02bc); base=struct.unpack_from('<Q',b,8)[0]
assert base==0x11c1000
# start, stack field, error path, continuation, diagnostic offset, candidate values
cases=[('focus_mode',0x11ff784,0xa0,0x11ffe48,0x11ff794,0x511fc0,[4,5,6,7]),('focus',0x11ff9c4,0xa4,0x1200088,0x11ff9d4,0x512590,[9,10,11,12]),('face',0x11ffaa4,0x98,0x1200168,0x11ffab4,0x5127a0,[3,4,5,6]),('subject',0x11ffac4,0x2e0,0x1200188,0x11ffad4,0x5127e8,[3,4,5,6])]
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM); rows=[]; descriptions=[]
for name,start,field,error,cont,stringoff,inputs in cases:
 code=[]
 for begin,end in [(start,cont),(error,error+16)]:
  code += [{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in cs.disasm(b[begin-base:end-base],begin)]
 descriptions.append({'name':name,'start':hex(start),'stack_offset':hex(field),'error_path':hex(error),'continuation':hex(cont),'diagnostic_address':hex(base+stringoff),'diagnostic':b[stringoff:b.index(b'\0',stringoff)].decode('ascii'),'instructions':code})
 for value in inputs:
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(base,(len(b)+4095)&~4095); u.mem_write(base,b)
  stack=0x70000000; u.mem_map(stack,0x10000); sp=stack+0x8000; u.reg_write(UC_ARM64_REG_SP,sp); u.mem_write(sp+field,struct.pack('<I',value)); calls=[]; trace=[]
  def hook(uc,address,size,user):
   trace.append(hex(address))
   if address==0x13ccc78:
    ptr=uc.reg_read(UC_ARM64_REG_X0); text=bytes(uc.mem_read(ptr,128)).split(b'\0',1)[0].decode('ascii'); calls.append({'target':hex(address),'x0':hex(ptr),'text':text}); uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
   elif address==cont: uc.emu_stop()
  u.hook_add(UC_HOOK_CODE,hook); u.emu_start(start,0,count=32)
  rows.append({'case':name,'input':value,'stack_offset':hex(field),'call_count':len(calls),'diagnostic':calls[0]['text'] if calls else '', 'trace':trace,'calls':calls,'stop_pc':hex(u.reg_read(UC_ARM64_REG_PC))})
result={'source':'Firmware на прочиеFuji/FPUPDATE.DAT','source_sha256':digest,'source_sha256_after':hashlib.sha256(src.read_bytes()).hexdigest(),'fflz_dat_offset':'0x9c02bc','decoded_sha256':hashlib.sha256(b).hexdigest(),'decoded_size':len(b),'assumed_base':hex(base),'method':'Unicorn ARM64, оригинальные инструкции; в 0x13ccc78 перехват вместо исполнения функции, затем возврат по LR; начальное содержимое стека синтетическое','cases':descriptions,'executions':rows}
assert result['source_sha256_after']==digest
(HERE/'доказательства.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with (HERE/'исполнения.tsv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.writer(f,delimiter='\t');w.writerow(['случай','вход_u32','смещение_стека','вызовов','диагностика','путь_PC','остановка']);
 for x in rows:w.writerow([x['case'],x['input'],x['stack_offset'],x['call_count'],x['diagnostic'],','.join(x['trace']),x['stop_pc']])
print(json.dumps({'cases':descriptions,'executions':rows},ensure_ascii=False,indent=2))
