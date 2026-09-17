# Replicate kernel/module.c layout_sections() for a .ko, to get runtime section offsets.
import subprocess, re, sys
ko = sys.argv[1]
out = subprocess.run(["readelf","-SW",ko],capture_output=True,text=True).stdout
secs=[]
for line in out.splitlines():
    m=re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)',line)
    if not m: continue
    idx,name,typ,addr,off,size,entsize,flags,lk,inf,al=m.groups()
    secs.append(dict(idx=int(idx),name=name,typ=typ,size=int(size,16),entsize=int(entsize,16),
                     flags=flags,align=int(al,16) or 1, sh_info=int(inf)))
SHF_WRITE=0x1; SHF_ALLOC=0x2; SHF_EXECINSTR=0x4
groups=[((SHF_EXECINSTR|SHF_ALLOC),0,'TEXT'),((SHF_ALLOC),(SHF_WRITE|SHF_EXECINSTR),'RO'),
        ((SHF_WRITE|SHF_ALLOC),0,'RW'),((SHF_ALLOC),0,'OTHER')]
def fl(s):
    v=0
    if 'W' in s: v|=SHF_WRITE
    if 'A' in s: v|=SHF_ALLOC
    if 'X' in s: v|=SHF_EXECINSTR
    return v
size=0; res={}
for mask,excl,tag in groups:
    for s in secs:
        f=fl(s['flags'])
        if (f & mask)!=mask: continue
        if excl and (f & excl): continue
        if s['idx'] in res: continue
        if not (f & SHF_ALLOC): continue
        if s['typ']=='RELA' or s['typ']=='REL' or s['typ']=='SYMTAB' or s['typ']=='STRTAB': continue
        if s['entsize'] and s['typ']!='PROGBITS' and s['typ']!='NOBITS': continue
        off=(size + s['align']-1)//s['align']*s['align']
        res[s['idx']]=(tag,s['name'],off,s['size'])
        size=off+s['size']
print(f"core_layout.size = 0x{size:x}")
for i in sorted(res):
    t,n,o,sz=res[i]
    print(f"  [{i:2}] {t:5} {n:34} off=0x{o:06x} size=0x{sz:x}")
