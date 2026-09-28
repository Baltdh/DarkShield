"""Bounded static control-flow tracing of scanner DLL exports; never executes them."""
import pathlib,json,hashlib,collections,pefile,capstone
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
r=pathlib.Path(__file__).parent;out=[]
for path in sorted((r/'extracted/VirusScanner').glob('*.dll')):
 if path.name not in ['ccScanw.dll','sds_loader_x86.dll','AvPreScn.dll']:continue
 data=path.read_bytes();p=pefile.PE(data=data);base=p.OPTIONAL_HEADER.ImageBase
 imports={i.address:d.dll.decode()+':'+(i.name.decode() if i.name else '#'+str(i.ordinal)) for d in getattr(p,'DIRECTORY_ENTRY_IMPORT',[]) for i in d.imports}
 md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
 def executable(addr):
  s=p.get_section_by_rva(addr-base)
  return s is not None and bool(s.Characteristics & 0x20000000)
 traces=[]
 for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
  if not exp.name or exp.forwarder:continue
  queue=collections.deque([(base+exp.address,0)]);seen=set();calls=set();instructions=0;indirect=0;branches=0
  while queue and len(seen)<64 and instructions<2048:
   addr,depth=queue.popleft()
   if addr in seen or not executable(addr):continue
   seen.add(addr)
   for ins in md.disasm(p.get_data(addr-base,512),addr):
    instructions+=1
    if instructions>2048:break
    if ins.mnemonic.startswith('ret'):break
    if ins.mnemonic=='call' or ins.mnemonic.startswith('j'):
     op=ins.operands[0] if ins.operands else None
     target=op.imm if op and op.type==X86_OP_IMM else None
     if op and op.type==X86_OP_MEM and not op.mem.base and not op.mem.index:
      name=imports.get(op.mem.disp & 0xffffffff)
      if name:calls.add(name)
      else:indirect+=1
     elif target is None:indirect+=1
     if ins.mnemonic=='call':
      if target is not None and depth<2:queue.append((target,depth+1))
     else:
      branches+=1
      if target is not None:queue.append((target,depth))
      if ins.mnemonic!='jmp':queue.append((ins.address+ins.size,depth))
      break
  traces.append({'export':exp.name.decode(),'entry_rva':hex(exp.address),'blocks':len(seen),'instructions':instructions,'named_import_references':sorted(calls),'unresolved_indirect_transfers':indirect,'pending_blocks':len(queue),'scope':'At most 64 blocks / 2048 instructions / two direct call levels; no runtime reachability proof.'})
 result={'module':path.name,'sha256':hashlib.sha256(data).hexdigest(),'exports':traces};out.append(result)
 print(path.name,json.dumps(traces),flush=True)
(r/'reports/Norton-export-traces.json').write_text(json.dumps(out,indent=2))
