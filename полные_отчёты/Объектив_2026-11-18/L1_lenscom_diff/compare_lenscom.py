from __future__ import annotations
import hashlib, json, re, struct, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[1]
sys.path.insert(0, str(ANALYSIS / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, insns, find_bytes, adrp_refs, bl_callers

OLD = load('X-H2', 'old', 0)
NEW = load('X-H2', 'new', 0)
V4 = json.loads((ANALYSIS / 'Фокус_2026-11-18' / 'V4_lenscom' / 'результат.json').read_text(encoding='utf-8'))
ENCODERS = V4['lenscom']['кодировщики']
SHIFT = 0x13dd448 - 0x13e6420
OLD_REG = 0x13e6420
NEW_REG = 0x13dd448
OLD_HANDLER = 0x13eb4dc
NEW_HANDLER = OLD_HANDLER + SHIFT
OLD_CLASSIFIER = 0x13e5408
NEW_CLASSIFIER = OLD_CLASSIFIER + SHIFT
OLD_SWITCH = 0x13ebb88
NEW_SWITCH = OLD_SWITCH + SHIFT
OLD_CASE_BASE = 0x13ebbec
NEW_CASE_BASE = OLD_CASE_BASE + SHIFT
OLD_TABLE = 0x1912414
NEW_TABLE = 0x1910654


def prologues(block, start, end):
    out=[]
    for va in range(start, end, 4):
        x=insns(block, va, 1)
        if x and x[0].mnemonic == 'stp' and x[0].op_str.startswith('x29, x30, [sp, #-') and x[0].op_str.endswith(']!'):
            out.append(va)
    return out


def fn_words(block, start, end):
    return insns(block, start, (end-start)//4)


def normalized(block, start, end):
    rows=[]
    page_regs=set()
    for x in fn_words(block,start,end):
        m, op=x.mnemonic, x.op_str
        if m == 'adrp':
            op=re.sub(r'#(?:0x[0-9a-f]+|\d+)', '<page>', op)
            page_regs.add(op.split(',')[0].strip())
        elif m == 'adr' and re.search(r'#(?:0x[0-9a-f]+|\d+)$',op):
            dst=int(re.search(r'#(0x[0-9a-f]+|\d+)$',op).group(1),0)
            op=f'<in:{dst-start:+#x}>' if start <= dst < end else '<external>'
        elif m == 'b' or m.startswith('b.') or m in ('bl','cbz','cbnz','tbz','tbnz'):
            mm=re.search(r'#(0x[0-9a-f]+|\d+)$',op)
            if mm:
                dst=int(mm.group(1),0)
                op=op[:mm.start()] + (f'<in:{dst-start:+#x}>' if start <= dst < end else '<external>')
        elif m == 'add' and re.fullmatch(r'x\d+, x\d+, #(?:0x[0-9a-f]+|\d+)',op):
            dst,src=op.split(',')[:2]
            if dst.strip()==src.strip() and dst.strip() in page_regs:
                # Normalize only ADRP + ADD address materialization; retain arithmetic immediates.
                op=re.sub(r'#(?:0x[0-9a-f]+|\d+)', '<low-page>',op)
        rows.append(f'{m} {op}'.rstrip())
    return rows


def sha(rows):
    return hashlib.sha256('\n'.join(rows).encode()).hexdigest()


def describe_fn(block, start, end):
    rows=normalized(block,start,end)
    return {'start':hex(start),'end':hex(end),'bytes':end-start,'инструкций':len(rows),'sha256_нормализованный':sha(rows),'нормализованные_инструкции':rows}


def end_for(block, start, starts, limit):
    if start in starts:
        return starts[starts.index(start)+1] if starts.index(start)+1<len(starts) else limit
    later=[x for x in starts if x>start]
    return min(later) if later else limit


oldstarts=prologues(OLD,0x13e5000,0x13ec800)
newstarts=prologues(NEW,0x13db000,0x13e3800)
oldmap={a:i+1 for i,a in enumerate(oldstarts)}
newmap={a:i+1 for i,a in enumerate(newstarts)}
old_end={a:(oldstarts[i+1] if i+1<len(oldstarts) else 0x13ec800) for i,a in enumerate(oldstarts)}
new_end={a:(newstarts[i+1] if i+1<len(newstarts) else 0x13e3800) for i,a in enumerate(newstarts)}

key_funcs=[('регистратор',OLD_REG,NEW_REG),('обработчик',OLD_HANDLER,NEW_HANDLER),('классификатор',OLD_CLASSIFIER,NEW_CLASSIFIER),('переключатель',OLD_SWITCH,NEW_SWITCH)]
functions=[]
for name, old, new in key_funcs:
    oldlimit=end_for(OLD,old,oldstarts,0x13ec800)
    newlimit=end_for(NEW,new,newstarts,0x13e3800)
    oo=describe_fn(OLD,old,oldlimit)
    nn=describe_fn(NEW,new,newlimit)
    functions.append({'роль':name,'5.30':oo,'5.33':nn,'совпадает':bool(oo and nn and oo['sha256_нормализованный']==nn['sha256_нормализованный'])})

coder_rows=[]
missing_old=[]; missing_new=[]
for p in ENCODERS:
    old=int(p['функция'],16)
    new=old+SHIFT
    # Check relocation and the encoded event constant/site.
    exists_old=old in old_end
    exists_new=new in new_end
    if not exists_old: missing_old.append(hex(old))
    if not exists_new: missing_new.append(hex(new))
    oo=describe_fn(OLD,old,old_end[old]) if exists_old else None
    nn=describe_fn(NEW,new,new_end[new]) if exists_new else None
    coder_rows.append({'код':hex(p['код']),'функция_5.30':hex(old),'функция_5.33':hex(new),'публикация_5.30':p['сайт_публикации'],'публикация_5.33':hex(int(p['сайт_публикации'],16)+SHIFT),'совпадает':bool(oo and nn and oo['sha256_нормализованный']==nn['sha256_нормализованный']),'5.30':oo,'5.33':nn})

def table_values(block, addr, n):
    o=block.off(addr)
    return list(struct.unpack_from('<'+'h'*n,block.data,o))

table_old=table_values(OLD,OLD_TABLE,0x1944-0x18d9+1)
table_new=table_values(NEW,NEW_TABLE,len(table_old))
table_old_targets=[OLD_CASE_BASE+v*4 for v in table_old]
table_new_targets=[NEW_CASE_BASE+v*4 for v in table_new]
table_change=[{'код':hex(0x18d9+i),'цель_5.30':hex(a),'цель_5.33':hex(b),'смещение_от_начала_переключателя_5.30':hex(a-OLD_SWITCH),'смещение_от_начала_переключателя_5.33':hex(b-NEW_SWITCH)} for i,(a,b) in enumerate(zip(table_old_targets,table_new_targets)) if a-OLD_SWITCH != b-NEW_SWITCH]

# Locate registration fields through the xref to the lenscom label and extract key values.
string_old=find_bytes(OLD,b'lenscom\0')[0]
string_new=find_bytes(NEW,b'lenscom\0')[0]

result={
  'версии':{'модель':'X-H2','5.30':OLD.version,'5.33':NEW.version,'блок':'0','база':hex(OLD.base)},
  'метод':'Статический ARM64 разбор локальных распакованных блоков; нормализация хэша удаляет адреса инструкций, заменяет страницы ADRP и внешние цели ветвлений; низкие смещения ADRP+ADD нормализованы отдельно от сравнения таблицы.',
  'смещение_кода_lenscom':hex(SHIFT),
  'строка_lenscom':{'5.30':hex(string_old),'5.33':hex(string_new),'регистратор_5.30':hex(OLD_REG),'регистратор_5.33':hex(NEW_REG),'ссылка_на_строку_5.30':adrp_refs(OLD,string_old),'ссылка_на_строку_5.33':adrp_refs(NEW,string_new)},
  'ключевые_функции':functions,
  'диспетчер':{'классификатор_5.30':hex(OLD_CLASSIFIER),'классификатор_5.33':hex(NEW_CLASSIFIER),'переключатель_5.30':hex(OLD_SWITCH),'переключатель_5.33':hex(NEW_SWITCH),'таблица_5.30':hex(OLD_TABLE),'таблица_5.33':hex(NEW_TABLE),'кодовый_диапазон':[hex(0x18d9),hex(0x1944)],'число_записей':len(table_old),'различия_смещений_целей':table_change,'хэш_целей_5.30':sha([hex(x-OLD_SWITCH) for x in table_old_targets]),'хэш_целей_5.33':sha([hex(x-NEW_SWITCH) for x in table_new_targets])},
  'кодировщики':coder_rows,
  'итог_кодировщиков':{'всего_5.30':len(ENCODERS),'хэш_совпадает':sum(r['совпадает'] for r in coder_rows),'различается':sum(not r['совпадает'] for r in coder_rows),'не_найдено_в_старой_области':missing_old,'не_найдено_в_новой_области':missing_new},
  'области_функций':{'5.30':[hex(oldstarts[0]),hex(oldstarts[-1]),len(oldstarts)],'5.33':[hex(newstarts[0]),hex(newstarts[-1]),len(newstarts)],'каждая_функция_имеет_соответствие_со_смещением':all((a+SHIFT) in newmap for a in oldstarts),'непарные_старые':[hex(a) for a in oldstarts if a+SHIFT not in newmap],'непарные_новые':[hex(a) for a in newstarts if a-SHIFT not in oldmap]},
}
(HERE/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

print('Functions old/new:',len(oldstarts),len(newstarts),'same relocation:',result['области_функций']['каждая_функция_имеет_соответствие_со_смещением'])
print('Key functions:',[(r['роль'],r['совпадает']) for r in functions])
print('Coders:',result['итог_кодировщиков'])
print('Tables:',len(table_old),len(table_change),'hashes equal:',result['диспетчер']['хэш_целей_5.30']==result['диспетчер']['хэш_целей_5.33'])
print('New dispatcher:',hex(NEW_SWITCH),'table:',hex(NEW_TABLE),'case base:',hex(NEW_CASE_BASE))
