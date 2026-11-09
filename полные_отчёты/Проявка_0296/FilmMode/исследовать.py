"""Исследование X-H2 5.30; DAT и предыдущие инструменты только читаются.
Python dependencies: unicorn, capstone, cryptography. Запуск: python исследовать.py
Все вызовы ARM64 используют искусственную память; не исполняется камера целиком.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'инструменты'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_PC

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location('prior', ROOT / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
sha = lambda b: hashlib.sha256(b).hexdigest()
source = prior.base.SOURCE
before = sha(source.read_bytes())
x = prior.Study()
a, b = x.a, x.b
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dis(block, base, start, end):
    return [f'{i.address:08x} {bytes(i.bytes).hex()}  {i.mnemonic} {i.op_str}' for i in md.disasm(block[start-base:end-base], start)]

def callsites(block, base, target):
    out=[]
    for off in range(0,len(block)-3,4):
        w=struct.unpack_from('<I',block,off)[0]
        if w & 0xfc000000 != 0x94000000: continue
        d=w & 0x3ffffff
        if d & 0x2000000: d-=0x4000000
        if base+off+4*d == target: out.append(base+off)
    return out

calls = [(hex(base),hex(addr)) for block,base in ((a,0x1101000),(b,0x29ae000)) for addr in callsites(block,base,0x2e516fc)]
store=[]
for block,base in ((a,0x1101000),(b,0x29ae000)):
    for off in range(0,len(block)-3,4):
        w=struct.unpack_from('<I',block,off)[0]
        if w & 0xffc00000 == 0xb9000000 and ((w>>10)&0xfff)*4 in (0x3974,0x3978,0x39b8,0x3f58,0x3f88):
            store.extend(dis(block,base,base+off,base+off+4))

rows=[]
p=0x60000000
for ui in (14,15,17,0,25,26,100):
    x.word(0x2051408,0)
    v=x.run(0x12e67ac,[0x68e,ui,0,3])
    err=x.u32(0x2051408)
    rows.append({'ui':ui,'mode':v,'error':err})

cases=[]
for gate,mode,other,f58,f88 in [(2,m,0,0,0) for m in range(0,25)]+[(0,19,0,0,0),(45,19,0,0,0),(45,19,1,0,0),(45,19,0,1,0),(45,19,0,1,1),(46,19,0,0,0)]:
    x.clear(p,0x8000)
    for off,v in ((0x3978,gate),(0x39b8,mode),(0x3974,other),(0x3f58,f58),(0x3f88,f88)): x.word(p+off,v)
    result=x.run(0x2e516fc,[p]) & 0xffffffff
    cases.append({'field_3978':gate,'field_39b8':mode,'field_3974':other,'field_3f58':f58,'field_3f88':f88,'return':hex(result)})

# UI-конвертер, setter, копирующий фрагмент и непосредственный caller.
# Значение UI->MODE вручную подается setter: это искусственная стыковка.
joined=[]
for ui in (14,15,17,0):
    frame,out=0x60010000,0x60020000
    x.clear(p,0x8000); x.clear(frame); x.clear(out)
    x.word(0x2051408,0)
    mode=x.run(0x12e67ac,[0x68e,ui,0,3])
    x.run(0x1562e18,[frame,mode])
    x.run(0x2e57320,until=0x2e57330,registers={20:p,21:frame})
    x.word(p+0x3978,2)
    x.run(0x2e537c8,until=0x2e537e4,registers={19:p,20:out})
    joined.append({'ui':ui,'mode':mode,'frame_c0':x.u32(frame+0xc0),
        'params_39b8':x.u32(p+0x39b8),'gate_3978':2,
        'output_190':hex(struct.unpack('<H',x.uc.mem_read(out+0x190,2))[0]),
        'valid_18c':x.u32(out+0x18c)})

assembly=['# 0x02e516fc; виртуальные адреса, байты из распакованного FFLZ 0x840274']+dis(b,0x29ae000,0x2e516fc,0x2e51858)
for _,s in calls:
    address=int(s,16); block,base=(a,0x1101000) if address<0x29ae000 else (b,0x29ae000)
    assembly += [f'\n# Прямой BL к 0x02e516fc: {s}']+dis(block,base,address-32,address+48)
for address in (0x2e1dad0,0x2e57058,0x2e5732c,0x2e601ec,0x308a964):
    assembly += [f'\n# Контекст возможной записи [base+0x39b8]: {address:#x}']+dis(b,0x29ae000,address-80,address+48)
for start,end in ((0x14f4ac8,0x14f4b60),(0x1562e10,0x1562e50)):
    assembly += [f'\n# Вызываемая функция {start:#x}']+dis(a,0x1101000,start,end)
assembly += ['\n# Все совпадения STR W с непосредственным смещением выбранных полей, сканирование двух распакованных блоков (не доказательство принадлежности структуре)']+store
(HERE/'инструкции.txt').write_text('\n'.join(assembly)+'\n',encoding='utf-8')
after=sha(source.read_bytes())
result={'sha256_before':before,'sha256_after':after,'decoded_blocks':[{'fflz_file_offset':'0x300274','virtual_base':'0x1101000','length':len(a),'sha256':sha(a)},{'fflz_file_offset':'0x840274','virtual_base':'0x29ae000','length':len(b),'sha256':sha(b)}], 'ui_to_representation_3':rows,'artificial_memory_cases':cases,'direct_bl_calls':calls,'store_instruction_candidates_count':len(store),'scope':'Aligned BL and STR W immediate scanned in both decoded blocks, including data; indirect calls and other encodings not covered; candidates not automatically classified.'}
result['artificial_joined_chain'] = joined
(HERE/'результат.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2,ensure_ascii=False))
