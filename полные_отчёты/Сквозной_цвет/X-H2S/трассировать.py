"""Модель X-H2S: только чтение DAT; исходные инструкции ARM64, искусственная память."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location('xh2s_prior', ROOT / 'Единый_глубокий_анализ/X-H2S/исследовать.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
from unicorn import UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

EXPECTED = '87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b'
P, FRAME, MID, OUT, GENERAL, REGS = (0x60000000, 0x60008000, 0x60010000, 0x60014000, 0x60020000, 0x60030000)
STOP = 0x70000000

def main():
    image = prior.Image()
    sha = hashlib.sha256(image.raw).hexdigest()
    assert sha == EXPECTED
    vm = prior.VM(image)
    u = vm.u
    u.mem_map(0xff96c000, 0x4000)
    u.mem_map(0xff000000, 0x1000)
    writes = []
    def capture(uc, access, address, size, value, user):
        if address in (0xff96c634, 0xff96c638):
            writes.append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)), 'address':hex(address), 'size':size, 'value':value})
    u.hook_add(UC_HOOK_MEM_WRITE, capture, begin=0xff96c000, end=0xff96ffff)
    def word(addr): return vm.u32(addr)
    def put(addr, value): vm.put32(addr, value & 0xffffffff)
    def run(start, end=STOP, args=None): vm.run(start, end, args)
    def s32(v): return v if v < 0x80000000 else v-0x100000000
    def convert(param, value, source, target):
        put(0x236b408, 0)
        run(0x1604da0, args={0:param, 1:value, 2:source, 3:target})
        return vm.x(0) & 0xffffffff, word(0x236b408)
    # Реальная таблица указателей, а не предположенная последовательность кодов.
    root = 0x1ef1aa8
    mode_table = vm.u64(root + 1677*8)
    color_table = vm.u64(root + 1714*8)
    assert (mode_table, color_table) == (0x1a783e8, 0x1a8cfb8)
    names = []
    for i in range(9):
        ptr = vm.u64(0x3539668 + 16*i)
        code = word(0x3539668 + 16*i+8)
        name = bytes(u.mem_read(ptr, 64)).split(b'\0')[0].decode('ascii')
        assert code == i and name.startswith('UI_STILLCOLOR_')
        names.append({'record':hex(0x3539668+16*i), 'string':hex(ptr), 'name':name, 'code':code})
    assert image.string(vm.u64(0x3525ac8)) == 'UI_SETP_STILLCOLOR' and word(0x3525ad0) == 1714
    assert image.string(vm.u64(0x3538f78)) == 'UI_FILM_SIM_CLASSIC_CHROME' and word(0x3538f80) == 14
    color_rows = []
    for ui in range(9):
        row = [word(color_table + ui*16 + j*4) for j in range(4)]
        native, err = convert(1714, ui, 0, 3)
        signed, err2 = convert(1714, ui, 0, 4)
        assert (native,err,signed,err2)==(row[2],0,row[3],0)
        assert native == ui and s32(signed)==(4-ui)*10
        u.mem_write(OUT, bytes(0x1000))
        run(0x324fe34, args={0:OUT,1:native,2:1,3:0})
        idx=word(OUT)
        assert idx == 8-ui
        color_rows.append({'ui_code':ui,'dictionary':names[ui], 'table_row_address':hex(color_table+ui*16), 'table_raw_u32':row, 'representation_4_signed':s32(signed), 'display_if_tenths':s32(signed)//10, 'native':native,'index':idx})
    assert [word(color_table+9*16+j*4) for j in range(4)]==[0xffff]*4
    keys = list(struct.unpack('<4I', image.read(0x3766458 + 5*16, 16)))
    assert keys == [0xaed8, 0xaeda, 0xaedc, 0xaede]
    raw_coefficients = [struct.unpack_from('<H', image.data, 0xc0274+k)[0] for k in keys]
    signed_coefficients = [v - 0x2000 if v & 0x1000 else v for v in raw_coefficients]
    assert signed_coefficients == [866, 996, -27, 69]
    cases=[]
    for ui in (0,14,17,18):
        row=[word(mode_table+ui*16+j*4) for j in range(4)]
        val,err=convert(1677,ui,0,3)
        assert (val,err)==(row[2],0)
        # Сравнение двух модельных глобалов и реальная ветка конвертер -> setter.
        put(0x236e100,ui); put(0x236bc70,0xffffffff); put(0x299c40c,0xffffffff)
        put(0x236b408,0)
        run(0x164b194,0x164b62c)
        state=word(0x299c40c)
        assert state == val and word(0x236b408)==0
        # Здесь граница: запись поля кадра вызвана исследователем, не firmware от state.
        u.mem_write(FRAME,bytes(0x1000)); run(0x18827c8,args={0:FRAME,1:state})
        assert word(FRAME+0xc0)==state
        u.mem_write(P,bytes(0x6000));u.mem_write(MID,bytes(0x1000))
        run(0x316e4a0,0x316e4b0,{21:FRAME,20:P})
        assert word(P+0x395c)==state
        run(0x3108d48,0x3108d50,{20:P,19:MID})
        assert word(MID+0x20)==state
        u.mem_write(OUT,bytes(0x1000))
        run(0x3250bdc,0x3250be8,{20:MID,19:OUT})
        mapped=word(OUT+0x130)
        cases.append({'ui':ui,'table_row':row,'conversion_native':val,'state':state,'frame_c0':word(FRAME+0xc0),'params_395c':word(P+0x395c),'intermediate_20':word(MID+0x20),'color_mode_130':mapped})
    assert cases[1]['color_mode_130']==8
    # Равные глобалы не должны идти по ветке записи.
    put(0x236e100,14);put(0x236bc70,14);put(0x299c40c,123)
    run(0x164b194,0x164b1ac)
    assert word(0x299c40c)==123
    matrix=[]
    # Вся дальнейшая цепь исполняется в одном экземпляре VM; context синтетический.
    for mode in cases:
      for color in color_rows:
        u.mem_write(P,bytes(0x1000));u.mem_write(OUT,bytes(0x1000));u.mem_write(GENERAL,bytes(0x1000));u.mem_write(REGS,bytes(0x1000))
        context={0x12c:1,0x130:mode['color_mode_130'],0x124:18,0x128:18,0x13c:color['index'],0x10c:8,0x17c:2,0x180:0}
        for off,v in context.items():put(P+off,v)
        run(0x323b004,args={0:P,1:OUT});selector=bytes(u.mem_read(OUT,1))[0]
        run(0x323b400,args={0:P,1:OUT});words=list(struct.unpack('<4h',u.mem_read(OUT+0x3c,8)))
        if mode['ui']==14:
            gain=image.data[0xc0274+0xaf50+color['index']]
            source=[signed_coefficients[i] for i in (0,2,1,3)]
            assert words==[max(-4096,min(4095,(v*gain*128*64)>>20)) for v in source]
        run(0x32335bc,0x32335d4,{19:P,21:GENERAL+0x96c})
        assembled=list(struct.unpack('<4h',u.mem_read(GENERAL+0xb46,8)))
        assert words==assembled and word(P+0x178)==0x80
        run(0x3233bb8,args={0:GENERAL,1:0x80,2:REGS})
        packed=list(struct.unpack('<4H',u.mem_read(REGS+0x1ec,8)))
        assert packed==[v&0x1fff for v in words]
        writes.clear();run(0x3233be4,args={0:0x80,1:REGS})
        expected=list(struct.unpack('<2I',struct.pack('<4H',*packed)))
        assert [(w['address'],w['size'],w['value']) for w in writes]==[('0xff96c634',4,expected[0]),('0xff96c638',4,expected[1])]
        matrix.append({'ui_mode':mode['ui'],'ui_color':color['ui_code'],'display_if_tenths':color['display_if_tenths'],'index':color['index'],'selector':selector,'gain_byte':image.data[0xc0274+0xaf50+color['index']],'words':words,'packed':packed,'writes':list(writes)})
    writes.clear();run(0x3233be4,args={0:0,1:REGS});assert not writes
    assert next(c for c in matrix if c['ui_mode']==14 and c['ui_color']==4)['words']==[866,-27,996,69]
    assert next(c for c in matrix if c['ui_mode']==14 and c['ui_color']==4)['selector']==6
    sha_after=hashlib.sha256(prior.SOURCE.read_bytes()).hexdigest();assert sha_after==sha
    result={'sha256_before':sha,'sha256_after':sha_after,'blocks':[{'address':hex(a),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for a,b in image.blocks], 'pc_checked_on_every_vm_run':True,'run_count':vm.count,'addresses':{'mode_table':hex(mode_table),'color_table':hex(color_table),'table_root':hex(root),'converter':'0x1604da0','compare':'0x164b194..0x164b1ac / 0x164b62c','state':'0x299c40c','frame_setter':'0x18827c8','frame_to_params':'0x316e4a0..0x316e4b0','params_offset':'0x395c','params_to_intermediate':'0x3108d48..0x3108d50','intermediate_to_color_mode':'0x3250bdc..0x3250be8','color_index':'0x324fe34','selector':'0x323b004','calculation':'0x323b400','assemble':'0x32335bc..0x32335d4','pack':'0x3233bb8','virtual_registers':'0x3233be4'},'synthetic_context':{'0x12c':1,'0x124':18,'0x128':18,'0x10c':8,'0x17c':2,'0x180':0},'color_dictionary_and_conversion':color_rows,'mode_cases':cases,'equal_comparison_preserves_state':True,'zero_mask_no_writes':True,'matrix':matrix,'limitations':['Исследователь переносит state в вызов setter кадра; путь между ними не доказан.','Число на дисплее выводится условно: representation_4 / 10; сам вывод меню не исполнен.','Остальной контекст синтетический; записи существуют только в Unicorn.']}
    result['classic_source_data']={'key_table_record':'0x37664a8','template_translated_dat_offset':'0xc0274','keys':[hex(k) for k in keys], 'raw_u16':raw_coefficients,'signed_13bit':signed_coefficients,'gain_offset':'0xaf50','gain_bytes':list(image.data[0xc0274+0xaf50:0xc0274+0xaf59]),'independent_integer_formula_checked_for_all_nine':True}
    (HERE/'Результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'runs':vm.count,'modes':cases,'classic_chrome':[r for r in matrix if r['ui_mode']==14 and r['ui_color'] in (0,4,8)],'sha256':sha},ensure_ascii=False,indent=2))

if __name__=='__main__': main()
