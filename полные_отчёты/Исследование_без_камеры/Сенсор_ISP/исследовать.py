"""Дескрипторы и исходные ARM64-циклы: виртуальная RAM, не камера."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FW = ROOT / 'Анализ_прошивки'
spec = importlib.util.spec_from_file_location('decoder', FW / 'анализ_файла.py')
decoder = importlib.util.module_from_spec(spec); spec.loader.exec_module(decoder)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
C = {
 'X-H2': ('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',0x300274,0x840274,0x60274,0x1e340,0x18dec58,0x1376914,0x1376948,0x1373e84,0x1373f30),
 'X-H2S': ('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',0x300274,0x840274,0x60274,0x1e340,0x1bfbe30,0x16944f4,0x1694528,0x1691a64,0x1691b10),
 'X-T5': ('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',0x300274,0x820274,0x60274,0x1e340,0x18dc718,0x13738e4,0x1373918,0x1370e54,0x1370f00),
 'X100VI': ('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',0x9c02bc,0x10e02bc,0x7f2bc,0x70000,0x19dbd38,0x145ec6c,0x145eca0,0x145c1dc,0x145c288),
}
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def listing(u, start, size):
 return [{'pc':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(start,size)),start)]
def sha(b): return hashlib.sha256(b).hexdigest()
out={'method':{'scope':'decoded low and two FFLZ blocks; second overlaid last; all aligned BL immediate candidates scanned, data may decode as BL; no indirect calls or other blocks', 'execution':'original ARM64 instructions in Unicorn; all source/destination/address-space values artificial; hooks observe synthetic RAM only', 'guard':'reader buffer initially 0xa5; mapped words and pair overwritten with artificial pattern; untouched bytes retained'}, 'models':{}}
COPY = {'X-H2':(0x1532bec,0x342cff8),'X-H2S':(0x185257c,0x375a7f8),'X-T5':(0x1528a00,0x3358a00),'X100VI':(0x15fc5dc,0x3653fc0)}
for name,(path,expected,ao,bo,lo,ln,table,writer,reader,gw,gr) in C.items():
 srcfile=ROOT/path; raw=srcfile.read_bytes(); before=sha(raw); assert before==expected
 data=raw.translate(decoder.TRANSLATION); a=decoder.unpack_fflz(data,ao); b=decoder.unpack_fflz(data,bo)
 blocks=[(0x40000,data[lo:lo+ln]),(struct.unpack_from('<Q',a,8)[0],a),(struct.unpack_from('<Q',b,8)[0],b)]
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
 for base,block in blocks:u.mem_write(base,block)
 u.mem_map(0x60000000,0x40000);u.mem_map(0x70000000,0x10000);u.mem_map(0xff000000,0x1000000)
 records=[]; pairs=[]
 for j in range(138):
  rec=bytes(u.mem_read(table+j*24,24)); addr,off,num=struct.unpack_from('<QQH',rec)
  records.append({'index':j,'bytes':rec.hex(),'address':hex(addr),'offset':hex(off),'count':num})
  pairs.extend((addr+4*k,off+4*k,j,k) for k in range(num))
 # Search direct callsites to wrapper entries in each raw decoded block, including overlaps.
 candidates={hex(writer):[],hex(reader):[]}
 for base,block in blocks:
  for off in range(0,len(block)-3,4):
   word=struct.unpack_from('<I',block,off)[0]
   if word>>26!=0x25:continue
   imm=word&0x3ffffff; imm=imm-(1<<26) if imm&(1<<25) else imm
   pc=base+off; dest=pc+(imm<<2)
   if hex(dest) in candidates:
    # Decode the actual selected overlaid bytes, not a possibly shadowed block.
    candidates[hex(dest)].append({'pc':hex(pc),'block_base':hex(base),'shadowed':bytes(u.mem_read(pc,4))!=block[off:off+4], 'window':listing(u,pc-0x20,0x44)})
 events=[]
 def hook(uc,access,address,size,value,user):events.append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hex(address),'size':size,'value':hex(value)})
 u.hook_add(UC_HOOK_MEM_WRITE,hook,begin=0xff000000,end=0xffffffff)
 def run(entry,args):
  for k in range(31):u.reg_write(getattr(R,'UC_ARM64_REG_X'+str(k)),0)
  u.reg_write(R.UC_ARM64_REG_SP,0x7000f000);u.reg_write(R.UC_ARM64_REG_X30,0x70000000)
  for k,v in enumerate(args):u.reg_write(getattr(R,'UC_ARM64_REG_X'+str(k)),v)
  u.emu_start(entry,0x70000000,count=200000,timeout=2000000)
  assert u.reg_read(R.UC_ARM64_REG_PC)==0x70000000
 buf=0x60000000; dest=buf+0x10000; size=0x4000
 # Deterministic nonconstant word stream, including holes.
 original=b''.join(struct.pack('<I',(0x9e3779b9*i+0x12345678)&0xffffffff) for i in range(size//4))
 u.mem_write(buf,original); events.clear();run(writer,[buf]); write_events=list(events)
 written={int(x['address'],16) for x in write_events}; expected_addrs={x[0] for x in pairs}
 before_pair=[struct.unpack('<I',u.mem_read(x,4))[0] for x in (0xff96c634,0xff96c638)]
 # Intervention after writer and before reader: only virtual RAM changes.
 u.mem_write(0xff96c634,struct.pack('<II',0x55667788,0xdeadbeef))
 u.mem_write(dest,b'\xa5'*size);events.clear();run(reader,[dest]); read_events=list(events)
 result=bytes(u.mem_read(dest,size)); covered={off+i for _,off,_,_ in pairs for i in range(4)}
 expected=bytearray(b'\xa5'*size)
 for addr,off,_,_ in pairs:expected[off:off+4]=bytes(u.mem_read(addr,4))
 mismatches=[i for i,(x,y) in enumerate(zip(result,expected)) if x!=y]
 # The actual next BL uses a second table of 303 pairs (destination offset, source offset).
 copy_fn,copy_table=COPY[name]
 copy_raw=bytes(u.mem_read(copy_table,303*16))
 mapping=[struct.unpack_from('<QQ',copy_raw,i*16) for i in range(303)]
 assert all(x+4<=size and y+4<=size for x,y in mapping)
 copy_dest=buf+0x20000;u.mem_write(copy_dest,b'\x5a'*size)
 copy_expected=bytearray(b'\x5a'*size)
 for x,y in mapping:copy_expected[x:x+4]=result[y:y+4]
 run(copy_fn,[copy_dest,dest,copy_table,303])
 copy_actual=bytes(u.mem_read(copy_dest,size))
 copy_bad=[i for i,(x,y) in enumerate(zip(copy_actual,copy_expected)) if x!=y]
 pair_locations=[{'source_offset':hex(y),'destination_offset':hex(x),'value':hex(struct.unpack_from('<I',copy_actual,x)[0])} for x,y in mapping if y in (0x1ec,0x1f0)]
 # Negative count control on the original copy routine, not a Python implementation.
 u.mem_write(copy_dest,b'\x5a'*size);run(copy_fn,[copy_dest,dest,copy_table,0])
 copy_zero_changed=sum(x!=0x5a for x in bytes(u.mem_read(copy_dest,size)))
 # Separately change omitted and duplicated fields; restart destination each time.
 u.mem_write(dest+0x49c,struct.pack('<I',0xaabbccdd))
 u.mem_write(copy_dest,b'\x5a'*size);run(copy_fn,[copy_dest,dest,copy_table,303])
 omit_actual=bytes(u.mem_read(copy_dest,size))
 u.mem_write(dest+0x490,struct.pack('<I',0x11223344))
 u.mem_write(copy_dest,b'\x5a'*size);run(copy_fn,[copy_dest,dest,copy_table,303])
 duplicate_actual=bytes(u.mem_read(copy_dest,size))
 alias_control={'omitted_source_offset':'0x49c','omitted_replacement':'0xaabbccdd','changed_destination_bytes_after_omitted_change':sum(a!=b for a,b in zip(copy_actual,omit_actual)),'duplicate_source_offset':'0x490','duplicate_replacement':'0x11223344','duplicate_destination_offsets':['0x56c','0x578'],'duplicate_destination_values':[hex(struct.unpack_from('<I',duplicate_actual,p)[0]) for p in (0x56c,0x578)]}
 copy_info={'entry':hex(copy_fn),'listing':listing(u,copy_fn,0x30),'table':hex(copy_table),'table_sha256':sha(copy_raw),'records':[{'index':i,'destination_offset':hex(x),'source_offset':hex(y)} for i,(x,y) in enumerate(mapping)],'pair_locations':pair_locations,'mismatch_count':len(copy_bad),'zero_count_changed_bytes':copy_zero_changed,'destination_unique_offsets':len({x for x,y in mapping}),'source_unique_offsets':len({y for x,y in mapping})}
 copy_info['alias_control']=alias_control
 # Negative control: reader of blank virtual RAM, no prior writer; separate Unicorn memory reset only.
 for addr in expected_addrs:u.mem_write(addr,b'\x00'*4)
 u.mem_write(dest,b'\xa5'*size);events.clear();run(reader,[dest]); zero=bytes(u.mem_read(dest,size))
 zero_bad=[i for i in range(size) if zero[i]!=(0 if i in covered else 0xa5)]
 model={'source':path,'sha256_before':before,'decoded_blocks':[{'base':hex(base),'length':len(block),'sha256':sha(block)} for base,block in blocks], 'table':hex(table),'table_sha256':sha(bytes(u.mem_read(table,138*24))),'records':records,'expanded_word_count':len(pairs),'unique_addresses':len(expected_addrs),'unique_buffer_offsets':len({p[1] for p in pairs}),'address_aliases':len(pairs)-len(expected_addrs),'offset_aliases':len(pairs)-len({p[1] for p in pairs}), 'offset_min':hex(min(p[1] for p in pairs)),'offset_max_inclusive':hex(max(p[1] for p in pairs)+3),'wrapper_writer':hex(writer),'wrapper_reader':hex(reader),'writer_asm':listing(u,writer,0x34),'reader_asm':listing(u,reader,0x34),'generic_writer_asm':listing(u,gw,0xac),'generic_reader_asm':listing(u,gr,0xac),'direct_bl_candidates':candidates,'experiment':{'input_formula':'(0x9e3779b9 * word_index + 0x12345678) mod 2^32','writer_event_count':len(write_events),'writer_events':write_events,'writer_missing_expected_addresses':[hex(x) for x in sorted(expected_addrs-written)],'writer_extra_addresses':[hex(x) for x in sorted(written-expected_addrs)],'pair_before_intervention':[hex(x) for x in before_pair],'virtual_intervention':['0x55667788','0xdeadbeef'],'pair_in_reader_buffer':[hex(x) for x in struct.unpack_from('<II',result,0x1ec)],'reader_virtual_write_events':read_events,'reader_buffer_mismatch_count':len(mismatches),'reader_buffer_mismatch_offsets':mismatches[:100], 'reader_zero_control_mismatch_count':len(zero_bad),'guard_bytes':size-len(covered),'scope_buffer_bytes':size}}
 model['sha256_after']=sha(srcfile.read_bytes());assert model['sha256_after']==before
 model['post_reader_copy']=copy_info
 out['models'][name]=model
 print(name,'calls', {k:len(v) for k,v in candidates.items()},'writer',len(write_events),'read mismatches',len(mismatches),'zero mismatches',len(zero_bad),flush=True)
(HERE/'результаты.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
