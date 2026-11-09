"""Local original ARM64 fragments in synthetic RAM; no photograph or camera execution."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = Path(__file__).resolve().parent
A = HERE.parents[1]
sys.path.insert(0, str(A / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', A / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
# chrome start/end, input offsets, WB preparation start/call, WB temperature, stack input offset
C = {
 'X-H2': (0x2df1d38, 0x2df1d48, 0x3f10, 0x3f14, 0x2de561c, 0x2de5658, 0x3a94, 0x98),
 'X-H2S': (0x3109330, 0x3109340, 0x3ebc, 0x3ec0, 0x30fcbfc, 0x30fcc38, 0x3a40, 0x98),
 'X-T5': (0x2d2f3b0, 0x2d2f3c0, 0x3f48, 0x3f4c, 0x2d22cc0, 0x2d22cfc, 0x3ad0, 0x98),
 'X100VI': (0x2ffabfc, 0x2ffac0c, 0x4538, 0x453c, 0x2fed93c, 0x2fed974, 0x40c0, 0xa8),
}
P, O, S, CAL = 0x60000000, 0x60010000, 0x70000000, 0x60020000
TEMPLATE_POINTER = {'X-H2':0x20c1458,'X-H2S':0x23dbc30,'X-T5':0x2066d90,'X100VI':0x211c1c8}
CONSUMER = {'X-H2':0x2f3a190,'X-H2S':0x3250f08,'X-T5':0x2e7548c,'X100VI':0x3150528}
SP = S + 0x8000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cases = [('strong_5750',2,2,5750), ('chrome_off',0,2,5750), ('blue_off',2,0,5750), ('both_off',0,0,5750), ('wb_5000',2,2,5000), ('off_5000',0,0,5000), ('invalid_3',3,3,5750)]
result = {'method': 'Each model: original instructions; synthetic RAM and registers, independently started fragments, no UI or camera; WB manually starts in the discriminator=10 branch. The calculator uses an artificial mode=13 and base DAT settings image manually attached, not real calibration.', 'cameras': {}}
for name, (cs, ce, co, boff, ws, we, temp, stack_in) in C.items():
    rel, expected, ao, b_off, _, _, template, _ = t.FILES[name]
    path = A.parent / rel
    raw = path.read_bytes(); before = hashlib.sha256(raw).hexdigest(); assert before == expected
    data = raw.translate(t.base.TRANSLATION)
    a, b = t.base.unpack_fflz(data, ao), t.base.unpack_fflz(data, b_off)
    ba, bb = struct.unpack_from('<Q',a,8)[0], struct.unpack_from('<Q',b,8)[0]
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM); uc.mem_map(ba, 0x6000000-ba); uc.mem_write(ba,a); uc.mem_write(bb,b)
    uc.mem_map(P,0x30000); uc.mem_map(S,0x10000)
    uc.mem_map(0x27008000,0x100000); uc.mem_write(0x27008000,data[template:template+0xc6c00])
    uc.mem_write(TEMPLATE_POINTER[name],struct.pack('<Q',0x27008000))
    reads, stack_reads = [], []
    def on_read(u, access, address, size, value, user):
        if P <= address < P+0x8000:
            reads.append({'pc':hex(u.reg_read(UC_ARM64_REG_PC)), 'offset':hex(address-P), 'size':size, 'bytes':bytes(u.mem_read(address,size)).hex()})
        if SP+stack_in+0x14 <= address < SP+stack_in+0x16:
            stack_reads.append({'pc':hex(u.reg_read(UC_ARM64_REG_PC)), 'address':hex(address), 'size':size})
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    def dis(start,end):
        block = b[start-bb:end-bb]
        return [{'pc':hex(i.address), 'bytes':i.bytes.hex(), 'asm':i.mnemonic+' '+i.op_str} for i in md.disasm(block,start)]
    rows=[]
    for label,ch,blue,k in cases:
        uc.mem_write(P,bytes(0x30000)); uc.mem_write(S,bytes(0x10000)); reads.clear()
        uc.mem_write(P+co,struct.pack('<I',ch)); uc.mem_write(P+boff,struct.pack('<I',blue)); uc.mem_write(P+temp,struct.pack('<H',k))
        uc.reg_write(UC_ARM64_REG_SP,SP); uc.reg_write(UC_ARM64_REG_X19,O); uc.reg_write(UC_ARM64_REG_X20,P); uc.reg_write(UC_ARM64_REG_X0,P+0x4000)
        uc.emu_start(cs,ce,count=1000); assert uc.reg_read(UC_ARM64_REG_PC)==ce
        uc.mem_write(SP+stack_in+8,struct.pack('<I',13))
        chrome_out = list(struct.unpack('<II',bytes(uc.mem_read(O+0x18c,8))))
        chrome_reads = list(reads); reads.clear()
        consumer = CONSUMER[name]
        uc.reg_write(UC_ARM64_REG_X19,CAL); uc.reg_write(UC_ARM64_REG_X20,O)
        uc.emu_start(consumer,consumer+24,count=10000); assert uc.reg_read(UC_ARM64_REG_PC)==consumer+24
        device_words = list(struct.unpack('<II',bytes(uc.mem_read(CAL+0x11c,8))))
        uc.reg_write(UC_ARM64_REG_X19,P); uc.reg_write(UC_ARM64_REG_X23,0); uc.reg_write(UC_ARM64_REG_X25,0)
        uc.emu_start(ws,we,count=10000); assert uc.reg_read(UC_ARM64_REG_PC)==we
        x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1); x2=uc.reg_read(UC_ARM64_REG_X2); x3=uc.reg_read(UC_ARM64_REG_X3)
        wb_input = bytes(uc.mem_read(SP+stack_in,0x30))
        wb_reads = list(reads)
        call_word = struct.unpack('<I',bytes(uc.mem_read(we,4)))[0]; assert call_word>>26 == 0b100101
        imm=call_word & 0x3ffffff; imm=imm-(1<<26) if imm & (1<<25) else imm
        callee=we+(imm<<2)
        stack_reads.clear()
        uc.reg_write(UC_ARM64_REG_X30,S)
        try:
            uc.emu_start(callee,S,count=100000)
            pc=uc.reg_read(UC_ARM64_REG_PC)
            outcome = 'returned' if pc==S else 'instruction_limit'
        except UcError as e:
            outcome = 'unicorn_error: '+str(e); pc=uc.reg_read(UC_ARM64_REG_PC)
        rows.append({'case':label, 'inputs':{'chrome':ch,'blue':blue,'temperature':k}, 'chrome_output_words':chrome_out, 'consumer_output_words':device_words, 'chrome_parameter_reads':chrome_reads, 'wb_parameter_reads':wb_reads, 'wb_call':{'target':hex(callee),'x0':hex(x0),'x1':hex(x1),'x2':x2,'x3':x3,'input_hex':wb_input.hex(),'temperature_word':struct.unpack_from('<H',wb_input,0x14)[0], 'temperature_field_reads':stack_reads,'synthetic_zero_context_attempt':outcome,'stop_pc':hex(pc),'output_hex':bytes(uc.mem_read(x1,0x20)).hex()}})
    after = hashlib.sha256(path.read_bytes()).hexdigest(); assert before==after
    result['cameras'][name]={'dat':rel,'sha256_before':before,'sha256_after':after,'offsets':{'chrome':hex(co),'blue':hex(boff),'wb_temperature':hex(temp)},'chrome_fragment':dis(cs,ce),'consumer_fragment':dis(consumer,consumer+24),'wb_fragment':dis(ws,we+4),'cases':rows}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({n:[{'case':r['case'],'chrome':r['chrome_output_words'],'wb':r['wb_call']['temperature_word'],'calculator':r['wb_call']['synthetic_zero_context_attempt']} for r in c['cases']] for n,c in result['cameras'].items()},ensure_ascii=False,indent=2))
