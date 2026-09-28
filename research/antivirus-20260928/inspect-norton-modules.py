"""Extract only three scanner modules from historical Norton archive, statically inspect."""
import pathlib,io,json,hashlib,pefile,py7zr,struct,subprocess,os
root=pathlib.Path(__file__).parent
report=json.loads((root/'reports/Norton-resources.json').read_text())
archive=next(x for x in report['embedded_7z'] if any(f['name']=='VirusScanner/ccScanw.dll' for f in x.get('files',[])))
targets=['VirusScanner/ccScanw.dll','VirusScanner/sds_loader_x86.dll','VirusScanner/AvPreScn.dll']
data=(root/'raw/Norton.exe').read_bytes();out=root/'extracted';out.mkdir(exist_ok=True)
with py7zr.SevenZipFile(io.BytesIO(data[archive['offset']:]),mode='r') as z:
 entries=z.list();assert sum(e.uncompressed for e in entries)<64*1024*1024
 assert all(not pathlib.PurePosixPath(e.filename).is_absolute() and '..' not in pathlib.PurePosixPath(e.filename).parts for e in entries)
 # py7zr cannot decode BCJ2. Use official 7-Zip for this archive.
 offset=archive['offset']; next_offset,next_size=struct.unpack_from('<QQ',data,offset+12)
 carved=root/'scanner-container.7z';carved.write_bytes(data[offset:offset+32+next_offset+next_size])
 subprocess.run([os.environ.get('SEVENZIP','7zz'),'x',str(carved),'-o'+str(out),'-y',*targets],check=True,timeout=90)
results=[]
for name in targets:
 p=out/name;d=p.read_bytes();pe=pefile.PE(data=d)
 m={'archive_offset':archive['offset'],'file':name,'size':len(d),'sha256':hashlib.sha256(d).hexdigest(),'imports':{},'exports':[]}
 for lib in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):m['imports'][lib.dll.decode(errors='replace')]=[x.name.decode(errors='replace') if x.name else '#'+str(x.ordinal) for x in lib.imports]
 if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):m['exports']=[x.name.decode(errors='replace') if x.name else '#'+str(x.ordinal) for x in pe.DIRECTORY_ENTRY_EXPORT.symbols]
 results.append(m);print(name,'DLL dependencies',list(m['imports']),'exports',m['exports'][:22],flush=True)
(root/'reports/Norton-scanner-modules.json').write_text(json.dumps(results,indent=2))
