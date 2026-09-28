"""Static PE inventory and bounded entry-point disassembly. Never executes input."""
import pathlib,hashlib,json,re,struct
import pefile,capstone
from cryptography.hazmat.primitives.serialization import pkcs7
root=pathlib.Path(__file__).parent
for path in (root/'raw').glob('*.exe'):
 data=path.read_bytes(); pe=pefile.PE(data=data)
 meta={'file':path.name,'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data),'machine':hex(pe.FILE_HEADER.Machine),'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'version':{},'sections':[],'imports':{},'certificates':[],'signature_validation':'NOT VERIFIED: certificate metadata only, no Authenticode digest, chain or revocation verification'}
 for block in getattr(pe,'FileInfo',[]):
  for info in block:
   for table in getattr(info,'StringTable',[]):meta['version'].update({k.decode(errors='replace'):v.decode(errors='replace') for k,v in table.entries.items()})
 for s in pe.sections: meta['sections'].append({'name':s.Name.rstrip(b'\0').decode(errors='replace'),'raw_size':s.SizeOfRawData,'virtual_size':s.Misc_VirtualSize,'entropy':round(s.get_entropy(),3)})
 for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):meta['imports'][d.dll.decode(errors='replace')]=[i.name.decode(errors='replace') if i.name else 'ordinal:'+str(i.ordinal) for i in d.imports]
 sec=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
 if sec.VirtualAddress and sec.Size:
  offset=sec.VirtualAddress;end=min(len(data),offset+sec.Size)
  while offset+8<=end:
   size,revision,kind=struct.unpack_from('<IHH',data,offset)
   if size<8 or offset+size>end:break
   if kind==2:
    try:
     for cert in pkcs7.load_der_pkcs7_certificates(data[offset+8:offset+size]):meta['certificates'].append({'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string(),'serial':hex(cert.serial_number)})
    except Exception as e:meta['certificate_parse_error']=str(e)
   offset+=(size+7)&~7
 off=pe.get_overlay_data_start_offset();meta['overlay_bytes']=len(data)-off if off else 0
 strings=[m.group().decode(errors='replace') for m in re.finditer(rb'[ -~]{7,}',data)]
 meta['packaging_markers']=[s[:200] for s in strings if any(k in s.lower() for k in ['inno setup','nullsoft','7-zip','bootstrapper','installer','avast','malwarebytes','norton'])][:45]
 md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if pe.FILE_HEADER.Machine==0x8664 else capstone.CS_MODE_32)
 rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint
 instructions=list(md.disasm(pe.get_data(rva,256),pe.OPTIONAL_HEADER.ImageBase+rva))[:32]
 meta['entry_analysis']={'instructions_decoded':len(instructions),'mnemonics':[i.mnemonic for i in instructions], 'control_transfers':[{'address':hex(i.address),'operation':i.mnemonic,'target':i.op_str} for i in instructions if i.mnemonic.startswith(('call','j','ret'))], 'scope':'First 32 entry-point instructions only; no full control flow or detection engine identified.'}
 out=root/'reports'/(path.stem+'-static.json');out.write_text(json.dumps(meta,indent=2))
 print(path.name,json.dumps({k:meta[k] for k in ['size_bytes','version','overlay_bytes','entry_analysis']}),flush=True)
