"""X100VI 1.31; DAT только чтение, обработка в памяти. Запуск: python исследовать.py.
FFLZ: существующий декодер fffw, лицензия в Анализ_прошивки/инструменты.
"""
from pathlib import Path
import csv, hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
AN = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X19, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

sha = lambda v: hashlib.sha256(v).hexdigest()
src = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
raw = src.read_bytes()
assert sha(raw) == '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
data = raw.translate(base.TRANSLATION)
r = base.unpack_fflz(data, 0x1402bc)
a = base.unpack_fflz(data, 0x9c02bc)
b = base.unpack_fflz(data, 0x10e02bc)
R, B = struct.unpack_from('<Q', r, 8)[0], struct.unpack_from('<Q', b, 8)[0]
assert (R, B) == (0x881000, 0x2b8f000)
keypath = AN / 'Сравнение_камер' / 'X100VI' / 'x100vi_pubkey.pem'
key = serialization.load_pem_public_key(keypath.read_bytes())
key.verify(raw[-72:], raw[:-72], ec.ECDSA(hashes.SHA256()))
# Негативный контроль: изменить только копию подписанных данных в памяти.
changed = bytearray(raw[:-72]); changed[0x204] ^= 1
try:
    key.verify(raw[-72:], bytes(changed), ec.ECDSA(hashes.SHA256()))
except InvalidSignature:
    tamper_rejected = True
else:
    raise AssertionError('Изменённые данные прошли проверку')
del changed
point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

sample = bytes.fromhex('44 33 22 11 88 77 66 55 cc bb aa 99 00 ff ee dd')
checks = []
for name, entry, stop, command, size, expected in [
    ('INIT', 0x3b25b8, 0x3b25f0, 0x600, 16, sample[:8]+sample[12:16]+sample[8:12]),
    ('START', 0x3b25fc, 0x3b2618, 0x602, 4, sample[:4]),
    ('WRITE', 0x3b263c, 0x3b2650, 0x603, 4, sample[:4]),
    ('DEINIT', 0x3b2680, 0x3b2694, 0x601, 4, sample[:4]),
]:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(B, (len(b)+4095)&~4095); uc.mem_write(B, b)
    uc.mem_map(0x20de000, 0x1000)
    uc.mem_map(0x60000000, 0x1000); uc.mem_write(0x60000000, sample)
    uc.mem_map(0x70000000, 0x10000); uc.reg_write(UC_ARM64_REG_SP, 0x7000f000)
    uc.reg_write(UC_ARM64_REG_X0, 0x60000000); uc.reg_write(UC_ARM64_REG_X19, 0x60000000)
    uc.emu_start(B+entry, B+stop, count=200)
    assert uc.reg_read(UC_ARM64_REG_PC) == B+stop
    cmd, length, ptr = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
    payload = bytes(uc.mem_read(ptr, length))
    assert (cmd, length, payload) == (command, size, expected)
    checks.append({'stage':name, 'entry_block_offset':hex(entry), 'stop_before_bl_block_offset':hex(stop), 'command':hex(cmd), 'payload_size':length, 'payload_hex':payload.hex(), 'input_hex':sample.hex(), 'entry_note': 'after prior call; X19 and SP synthetic' if name in ('WRITE','DEINIT') else 'function entry'})

# Внешние службы подменены только для локальной проверки создания сообщения.
recovery = []
for value, service_result in [(v, 0) for v in range(21)] + [(0xffffffff,0), (0,1), (18,1)]:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(R, (len(r)+4095)&~4095); uc.mem_write(R, r)
    uc.mem_map(0x70000000, 0x10000); uc.reg_write(UC_ARM64_REG_SP, 0x7000f000)
    uc.mem_map(0x71000000, 0x1000)
    uc.reg_write(UC_ARM64_REG_X0, value); uc.reg_write(UC_ARM64_REG_X30, 0x71000000)
    calls = []
    def hook(u, addr, size, user):
        off = addr-R
        if off == 0x3d14:
            calls.append({'target':'0x3d14', 'stub_return':0x1234})
            u.reg_write(UC_ARM64_REG_X0, 0x1234); u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))
        elif off == 0x49e0:
            x0=u.reg_read(UC_ARM64_REG_X0); p=u.reg_read(UC_ARM64_REG_X1)
            msg=bytes(u.mem_read(p, 24)); payloadptr=struct.unpack_from('<Q',msg,16)[0]
            calls.append({'target':'0x49e0','x0':hex(x0),'header_hex':msg.hex(),'id':hex(struct.unpack_from('<H',msg,0)[0]),'source':hex(struct.unpack_from('<H',msg,2)[0]),'destination':hex(struct.unpack_from('<H',msg,4)[0]),'size':struct.unpack_from('<I',msg,8)[0], 'payload':struct.unpack('<I',bytes(u.mem_read(payloadptr,4)))[0], 'stub_return':service_result})
            u.reg_write(UC_ARM64_REG_X0,service_result); u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(R+0x1514,0x71000000,count=200)
    assert uc.reg_read(UC_ARM64_REG_PC)==0x71000000
    ret=uc.reg_read(UC_ARM64_REG_X0)&0xffffffff
    assert ret == (0 if value<=18 and service_result==0 else 0xfffffffa)
    assert len(calls)==(2 if value<=18 else 0)
    if value<=18:
        assert (calls[1]['id'],calls[1]['source'],calls[1]['destination'],calls[1]['size'],calls[1]['payload']) == ('0x148a','0x1234','0xea',4,value)
    recovery.append({'input':value,'message_service_return':service_result,'return_w0':hex(ret),'calls':calls})

labels = {}
for name in ['A_UPDATE_DEINIT','A_UPDATE_INIT','A_UPDATE_START','A_UPDATE_WRITE','UI_ERR_UPDATE_NO_FILE','UI_ERR_UPDATE_BROKEN_FILE','UI_ERR_UPDATE_OLD_FILE','UI_ERR_UPDATE_MODEDIFFER','UI_ERR_UPDATE_FAILURE']:
    off=a.find(name.encode()+b'\0'); labels[name]=hex(off) if off>=0 else None
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
regions=[('recovery_selector',r,0x1514,0x159c),('recovery_filename',r,0x82a64,0x82b38),('update_helpers',b,0x3b2570,0x3b26a4),('update_handlers',b,0xa513c,0xa54f8),('normal_filename',b,0x597e14,0x597ef8)]
lines=[]
for name,buf,start,end in regions:
    lines.append(f'; {name} распакованный блок +{start:#x}..+{end:#x}, условная база 0')
    lines.extend(f'{i.address:08x}  {i.bytes.hex(" "):11}  {i.mnemonic:8} {i.op_str}' for i in cs.disasm(buf[start:end],start))
(HERE/'команды.asm').write_text('\n'.join(lines)+'\n',encoding='utf-8')
with (HERE/'тесты.tsv').open('w',encoding='utf-8',newline='') as f:
    w=csv.writer(f,delimiter='\t',lineterminator='\n'); w.writerow(['type','input_or_stage','service_return','result','payload'])
    for x in checks: w.writerow(['request',x['stage'],'not called',x['command'],x['payload_hex']])
    for x in recovery: w.writerow(['recovery',x['input'],x['message_service_return'],x['return_w0'],x['calls'][-1].get('payload','') if x['calls'] else ''])
after=sha(src.read_bytes()); assert after==sha(raw)
result={'source':str(src.relative_to(ROOT)), 'source_size':len(raw),'source_sha256':sha(raw),'source_sha256_after':after,'xor':'ff in memory','blocks':{'recovery':{'dat_offset':'0x1402bc','sha256':sha(r),'bytes':len(r),'conditional_base':hex(R)},'main_labels':{'dat_offset':'0x9c02bc','sha256':sha(a),'bytes':len(a)},'update':{'dat_offset':'0x10e02bc','sha256':sha(b),'bytes':len(b),'conditional_base':hex(B)}},'signature':{'algorithm':'ECDSA secp256r1 SHA-256','signature_offset':hex(len(raw)-72),'signature_bytes':72,'signed_prefix_bytes':len(raw)-72,'valid':True,'modified_copy_rejected':tamper_rejected,'public_key_path':str(keypath.relative_to(ROOT)),'public_key_sha256':sha(keypath.read_bytes()),'public_point_in_xor_dat':hex(data.find(point)) if point in data else None},'labels_main_block_offsets':labels,'request_runs':checks,'recovery_selector_runs':recovery,'limits':['conditional bases are not proven runtime addresses','no transport or hardware execution','WRITE and DEINIT snippets start after a skipped call','recovery service calls are synthetic stubs','signature verification on host does not establish camera verification order']}
filename_table = r[0x179380:0x179380+6*17]
assert filename_table == b[0x82a1a0:0x82a1a0+6*17]
result['filename_table'] = {'recovery_offset':'0x179380','update_offset':'0x82a1a0','stride':17,'names':[filename_table[i:i+17].split(b'\0')[0].decode('ascii') for i in range(0,len(filename_table),17)],'interpretation':'static tables; no demonstrated file open'}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'sha256':sha(raw),'signature_valid':True,'request_runs':checks,'recovery_runs':len(recovery),'labels':labels},ensure_ascii=False,indent=2))
