"""Поиск потребителей выходного поля X-H2. DAT только читается.
Запуск из любого каталога: python исследовать.py. Требуются capstone, unicorn, cryptography.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location('prior', ROOT / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
prior = importlib.util.module_from_spec(spec); spec.loader.exec_module(prior)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
sha = lambda data: hashlib.sha256(data).hexdigest()
before = sha(prior.base.SOURCE.read_bytes())
x = prior.Study()
blocks = [(x.a, 0x1101000), (x.b, 0x29ae000)]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dis(start, end):
    for block, base in blocks:
        if base <= start and end <= base + len(block):
            return [f'{i.address:08x} {bytes(i.bytes).hex()} {i.mnemonic} {i.op_str}' for i in md.disasm(block[start-base:end-base], start)]
    return []
def calls(target):
    result = []
    for block,base in blocks:
        for off in range(0,len(block)-3,4):
            w=struct.unpack_from('<I',block,off)[0]
            if w & 0xfc000000 != 0x94000000: continue
            d=w & 0x3ffffff
            if d & 0x2000000: d-=0x4000000
            if base+off+4*d==target: result.append(base+off)
    return result
hits = {'ldrh_190':[], 'strh_190':[], 'ldr_18c':[], 'str_18c':[], 'mov_1401':[]}
for block,base in blocks:
    for off in range(0,len(block)-3,4):
        w=struct.unpack_from('<I',block,off)[0]; addr=base+off
        for name,opcode,scale,offset in [('ldrh_190',0x79400000,2,0x190),('strh_190',0x79000000,2,0x190),('ldr_18c',0xb9400000,4,0x18c),('str_18c',0xb9000000,4,0x18c)]:
            if w & 0xffc00000 == opcode and ((w>>10)&0xfff)*scale == offset:
                hits[name].append(addr)
        if w & 0xffe00000 in (0x52800000, 0xd2800000) and (w>>5)&0xffff == 0x1401:
            hits['mov_1401'].append(addr)
paired=[]
for a in hits['ldrh_190']:
    for b in hits['ldr_18c']:
        if abs(a-b)<=160:
            ia=dis(a,a+4)[0]; ib=dis(b,b+4)[0]
            paired.append({'halfword':hex(a),'flag':hex(b),'halfword_instruction':ia,'flag_instruction':ib,'context':dis(min(a,b)-40,max(a,b)+80)})
result={'sha256_before':before,'decoded_blocks':[{'base':hex(base),'length':len(block),'sha256':sha(block)} for block,base in blocks], 'counts':{k:len(v) for k,v in hits.items()}, 'hits':{k:[hex(v) for v in values] for k,values in hits.items()},'nearby_loads':paired,
 'writers':[{'address':hex(a),'context':dis(a-48,a+56)} for a in (0x2e537d0,0x2e55410)],
 'constant_contexts':[{'address':hex(a),'context':dis(a-16,a+24)} for a in hits['mov_1401']],
 'scope':'Aligned ARM64 unsigned immediate loads/stores, both decoded blocks incl data; same offsets do not establish same object; no unscaled, pair, register offset, vector, indirect alias, memcpy, other blocks, or reachability coverage.'}
result['instruction_contexts'] = {hex(a):dis(a,b) for a,b in [
    (0x2e51d48,0x2e51d7c),(0x2e54f84,0x2e54fac),
    (0x2e7a7a0,0x2e7a7bc),(0x2f1d10c,0x2f1d120),
    (0x2f1d3ec,0x2f1d404),(0x134df8c,0x134dfb0),
    (0x134e08c,0x134e100),(0x134e138,0x134e160),
    (0x134e1ac,0x134e1b8),(0x134e26c,0x134e284),
    (0x134fd68,0x134fdf4),(0x13503e4,0x1350474),
    (0x1350514,0x135064c),(0x134fa64,0x134fb04),
    (0x134fb8c,0x134fba8),(0x134f920,0x134f980),
    (0x134fa34,0x134fa64),(0x134fbf0,0x134fc50),
    (0x133f640,0x133f6b0)]}
result['direct_calls'] = {hex(a):[hex(v) for v in calls(a)] for a in
    (0x2e51d48,0x2e54f84,0x2f1d10c,0x134df8c,0x134fa64,0x134fbf0,0x13503e4)}
descriptor = 0x18d49f8
result['descriptor'] = {'address':hex(descriptor), 'bytes':x.a[descriptor-0x1101000:descriptor-0x1101000+40].hex(' ')}

# Карта RAM и имена ниже искусственные. Исполняются настоящие команды,
# включая обход всей таблицы 2 и построение каждого каталога, не только тег.
for addr in (0x260c000,0x2430000,0x229b000,0x2055000,0x253a000):
    x.uc.mem_map(addr,0x1000)
params, obj, buf, copy = 0x60000000, 0x60010000, 0x60020000, 0x60030000
cases=[]
for mode in (13,19,22,0,4):
    for override in (None,0):
        x.clear(params,0x8000); x.clear(obj,0x10000); x.clear(buf,0x10000); x.clear(copy)
        for addr in (0x260c000,0x2430000,0x229b000,0x2055000,0x253a000):
            x.clear(addr)
        x.word(params+0x3978,2); x.word(params+0x39b8,mode)
        x.run(0x2e537c8,until=0x2e537e4,registers={19:params,20:obj})
        if override is not None: x.word(obj+0x18c,override)
        val=bytes(x.uc.mem_read(obj+0x190,2))
        valid=x.u32(obj+0x18c)
        accepted=x.run(0x134df8c,[2,0x1401,obj])
        x.run(0x2f1d3f4,until=0x2f1d404,registers={19:copy,20:obj})
        count=x.run(0x13503e4,[2,obj,buf,buf])
        data=bytes(x.uc.mem_read(buf,count))
        prefix=bytes.fromhex('01 14 03 00 01 00 00 00')
        locations=[i for i in range(len(data)-11) if data[i:i+8]==prefix]
        cases.append({'mode':mode,'gate_3978':2,'override_valid':override,
            'value_bytes':val.hex(' '),'valid_18c':valid,'predicate':accepted,
            'copy_valid_u32':x.u32(copy+0x160),'copy_value_u32':x.u32(copy+0x164),
            'directory_length':count,'record_offsets':locations,
            'records':[data[i:i+12].hex(' ') for i in locations],
            'directory_sha256':sha(data)})
x.clear(buf,0x1000)
x.clear(0x2430000)
header_size=x.run(0x134fbf0,[buf])
result['vm']={'description':'Artificial separately joined writer, field-copy fragment, predicate and directory-builder; zero-filled globals; not a camera capture.',
    'params':hex(params),'object':hex(obj),'directory_buffer':hex(buf),'copy':hex(copy),
    'zero_filled_ram':['0x260c000','0x2430000','0x229b000','0x2055000','0x253a000'],
    'cases':cases,'maker_header_bytes':bytes(x.uc.mem_read(buf,header_size)).hex(' ')}
color_cases=[]
for color in (3,4,2):
    x.clear(params,0x8000); x.clear(obj,0x10000); x.clear(buf,0x10000)
    for addr in (0x260c000,0x2430000,0x229b000,0x2055000,0x253a000): x.clear(addr)
    x.word(params+0x3978,2); x.word(params+0x39b8,19); x.word(params+0x39b4,color)
    x.run(0x2e552a4,until=0x2e552b0,registers={19:params,20:obj})
    value=bytes(x.uc.mem_read(obj+0x9a,2))
    accepted=x.run(0x134df8c,[2,0x1003,obj])
    length=x.run(0x13503e4,[2,obj,buf,buf])
    data=bytes(x.uc.mem_read(buf,length))
    prefix=bytes.fromhex('03 10 03 00 01 00 00 00')
    locations=[i for i in range(len(data)-11) if data[i:i+8]==prefix]
    color_cases.append({'field_39b4':color,'output_9a_bytes':value.hex(' '),
        'predicate':accepted,'directory_length':length,'record_offsets':locations,
        'records':[data[i:i+12].hex(' ') for i in locations]})
result['vm']['saturation_controls']=color_cases

# Сопоставление по структуре дескриптора, а не по одному 0x1401.
models=[
 ('X-H2S','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],[0x1421000,0x2cca000]),
 ('X-T5','Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],[0x1101000,0x28eb000]),
 ('X100VI','Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],[0x11c1000,0x2b8f000])]
comparisons=[]
for name,path,expected,offsets,bases in models:
    file=ROOT.parent/path
    raw=file.read_bytes(); digest=sha(raw)
    if digest!=expected: raise ValueError(f'{name}: unexpected DAT hash {digest}')
    decoded=raw.translate(prior.base.TRANSLATION); found=[]; block_info=[]
    for off,base in zip(offsets,bases):
        block=prior.base.unpack_fflz(decoded,off)
        if struct.unpack_from('<Q',block,8)[0]!=base: raise ValueError(f'{name}: unexpected base')
        block_info.append({'fflz_offset':hex(off),'base':hex(base),'length':len(block),'sha256':sha(block)})
        pos=0
        while True:
            pos=block.find(bytes.fromhex('01 14'),pos)
            if pos<0: break
            if pos%2==0 and pos+40<=len(block) and block[pos+4:pos+8]==bytes.fromhex('03 00 01 00') and block[pos+8:pos+16]==bytes(8):
                found.append({'address':hex(base+pos),'bytes':block[pos:pos+40].hex(' '),
                    'source_offset':hex(struct.unpack_from('<Q',block,pos+32)[0])})
            pos+=2
    after_other=sha(file.read_bytes())
    comparisons.append({'model':name,'file':path,'sha256_before':digest,'sha256_after':after_other,'blocks':block_info,'descriptor_candidates':found})
    if after_other!=digest: raise RuntimeError(f'{name}: input changed')
result['other_models']=comparisons
result['sha256_after']=sha(prior.base.SOURCE.read_bytes())
if result['sha256_after']!=before: raise RuntimeError('X-H2 input changed')
(HERE/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'counts':result['counts'],'vm':result['vm'],'other_models':comparisons},ensure_ascii=False,indent=2))
