"""Read PE resources and embedded archive metadata without executing vendor code."""
import pathlib,pefile,json,io,py7zr,lzma,hashlib
root=pathlib.Path(__file__).parent
for f in (root/'raw').glob('*.exe'):
 d=f.read_bytes();p=pefile.PE(data=d);records=[]; decoded=[]
 if hasattr(p,'DIRECTORY_ENTRY_RESOURCE'):
  for kind in p.DIRECTORY_ENTRY_RESOURCE.entries:
   for item in kind.directory.entries:
    for lang in item.directory.entries:
     x=lang.data.struct;data=p.get_data(x.OffsetToData,x.Size)
     records.append({'type':str(kind.name or kind.id),'name':str(item.name or item.id),'size':x.Size,'prefix_hex':data[:12].hex()})
     if str(kind.name)=='LZMA':
      try:
       dec=lzma.LZMADecompressor(memlimit=128*1024*1024); blob=dec.decompress(data,max_length=16*1024*1024)
       decoded.append({'resource':str(item.name or item.id),'size':len(blob),'complete':dec.eof,'sha256':hashlib.sha256(blob).hexdigest(),'prefix_hex':blob[:12].hex()})
      except Exception as e:decoded.append({'error':str(e)})
 archives=[]; start=0
 for _ in range(12):
  offset=d.find(b'7z\xbc\xaf\x27\x1c',start)
  if offset<0:break
  start=offset+6
  try:
   with py7zr.SevenZipFile(io.BytesIO(d[offset:]),mode='r') as z:
    entries=z.list();archives.append({'offset':offset,'entry_count':len(entries),'files':[{'name':e.filename,'size':e.uncompressed,'directory':e.is_directory} for e in entries]})
  except Exception as e:archives.append({'offset':offset,'parse_error':str(e)[:180]})
 v={'file':f.name,'resource_inventory':records,'lzma_resources':decoded,'embedded_7z':archives}
 (root/'reports'/(f.stem+'-resources.json')).write_text(json.dumps(v,indent=2)); print(f.name,'LZMA',decoded,'7z',[(a['offset'],a.get('entry_count'),a.get('parse_error')) for a in archives],flush=True)
